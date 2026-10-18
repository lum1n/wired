// Package wired embeds a Wired node: encrypted service-to-service networking
// that works across NATs, set up with a single invite string.
//
//	vps, _ := wired.Anchor(wired.AnchorOptions{Name: "vps"})
//	fmt.Println(vps.Invite())
//
//	laptop, _ := wired.Join(wired.JoinOptions{Name: "laptop"}) // reads WIRED_INVITE
//	ln, _ := laptop.Listen("api")
//	go http.Serve(ln, handler)
//
//	resp, _ := vps.HTTPClient().Get("http://api.laptop.wired/")
package wired

/*
#include <stdlib.h>
#include "wired.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

// JoinOptions configures a member node.
type JoinOptions struct {
	Name string
	// Invite defaults to the WIRED_INVITE environment variable.
	Invite string
	// StateDir defaults to $XDG_CONFIG_HOME/wired.
	StateDir string
	// Ephemeral keeps keys in memory only.
	Ephemeral bool
}

// AnchorOptions configures an anchor, which runs on a publicly reachable host.
type AnchorOptions struct {
	Name string
	// BindHost defaults to 0.0.0.0.
	BindHost string
	// Port is the UDP port for peers and the TCP port for the relay (default 7443).
	Port uint16
	// QADPort is the UDP port for address discovery (default 7842).
	QADPort uint16
	// NoQAD disables QUIC address discovery.
	NoQAD bool
	// AnyPorts lets the OS pick every port (tests).
	AnyPorts bool
	// PublicHost is the host or IP put in the invite (default: the default route's IP).
	PublicHost string
	// ReplicaOf makes this a replica of the network with this invite. Approve
	// it on the root anchor with ApproveAnchor (or `wired approve <id>`).
	ReplicaOf string
	StateDir  string
	Ephemeral bool
}

// Node is an embedded Wired node. Safe for concurrent use.
type Node struct {
	mu sync.RWMutex
	p  *C.WiredNode
}

// ErrClosed is returned when using a closed node or listener.
var ErrClosed = errors.New("wired: closed")

// Join joins a network as a member.
func Join(o JoinOptions) (*Node, error) {
	name, inv, dir := cstr(o.Name), cstr(o.Invite), cstr(o.StateDir)
	defer freeC(name)
	defer freeC(inv)
	defer freeC(dir)
	var p *C.WiredNode
	var cerr *C.char
	if C.wired_join(name, inv, dir, cbool(o.Ephemeral), &p, &cerr) != 0 {
		return nil, takeErr(cerr)
	}
	return &Node{p: p}, nil
}

// Anchor starts an anchor node and its relay.
func Anchor(o AnchorOptions) (*Node, error) {
	port, qad := C.uint16_t(7443), C.int32_t(7842)
	if o.Port != 0 {
		port = C.uint16_t(o.Port)
	}
	if o.QADPort != 0 {
		qad = C.int32_t(o.QADPort)
	}
	if o.AnyPorts {
		port, qad = 0, 0
	}
	if o.NoQAD {
		qad = -1
	}
	name, host, pub, rep, dir := cstr(o.Name), cstr(o.BindHost), cstr(o.PublicHost), cstr(o.ReplicaOf), cstr(o.StateDir)
	defer freeC(name)
	defer freeC(host)
	defer freeC(pub)
	defer freeC(rep)
	defer freeC(dir)
	var p *C.WiredNode
	var cerr *C.char
	if C.wired_anchor(name, host, port, qad, pub, rep, dir, cbool(o.Ephemeral), &p, &cerr) != 0 {
		return nil, takeErr(cerr)
	}
	return &Node{p: p}, nil
}

func (n *Node) handle() (*C.WiredNode, func(), error) {
	n.mu.RLock()
	if n.p == nil {
		n.mu.RUnlock()
		return nil, nil, ErrClosed
	}
	return n.p, n.mu.RUnlock, nil
}

func (n *Node) str(f func(*C.WiredNode) *C.char) string {
	p, done, err := n.handle()
	if err != nil {
		return ""
	}
	defer done()
	return goString(f(p))
}

// Name is this node's name in the network.
func (n *Node) Name() string {
	return n.str(func(p *C.WiredNode) *C.char { return C.wired_node_name(p) })
}

// ID is this node's public key.
func (n *Node) ID() string {
	return n.str(func(p *C.WiredNode) *C.char { return C.wired_node_id(p) })
}

// Invite is the network invite. On an anchor, hand it to other nodes; it is a credential.
func (n *Node) Invite() string {
	return n.str(func(p *C.WiredNode) *C.char { return C.wired_node_invite(p) })
}

// IsRoot reports whether this is the root anchor, where new nodes join and
// admin changes happen.
func (n *Node) IsRoot() bool {
	p, done, err := n.handle()
	if err != nil {
		return false
	}
	defer done()
	return C.wired_node_is_root(p) != 0
}

// Member is a node in the network.
type Member struct {
	Name   string
	ID     string
	Anchor bool
}

// Members lists the network's nodes, as last synced from an anchor.
func (n *Node) Members() []Member {
	var out []Member
	for _, line := range strings.Split(n.str(func(p *C.WiredNode) *C.char { return C.wired_members(p) }), "\n") {
		if f := strings.Split(line, "\t"); len(f) == 3 {
			out = append(out, Member{Name: f[0], ID: f[1], Anchor: f[2] == "anchor"})
		}
	}
	return out
}

// Revoke removes a node now (root only). Every node drops it, and the invite
// is rotated; the new invite is returned.
func (n *Node) Revoke(name string) (string, error) {
	return n.inviteCall(func(p *C.WiredNode, out **C.char, cerr **C.char) C.int {
		cn := cstr(name)
		defer freeC(cn)
		return C.wired_revoke(p, cn, out, cerr)
	})
}

// RotateInvite replaces the invite (root only); existing members are unaffected.
func (n *Node) RotateInvite() (string, error) {
	return n.inviteCall(func(p *C.WiredNode, out **C.char, cerr **C.char) C.int {
		return C.wired_rotate_invite(p, out, cerr)
	})
}

func (n *Node) inviteCall(f func(*C.WiredNode, **C.char, **C.char) C.int) (string, error) {
	p, done, err := n.handle()
	if err != nil {
		return "", err
	}
	defer done()
	var out, cerr *C.char
	if f(p, &out, &cerr) != 0 {
		return "", takeErr(cerr)
	}
	return goString(out), nil
}

// ApproveAnchor lets the replica anchor with this node id join (root only).
func (n *Node) ApproveAnchor(id string) error {
	p, done, err := n.handle()
	if err != nil {
		return err
	}
	defer done()
	cid := cstr(id)
	defer freeC(cid)
	var cerr *C.char
	if C.wired_approve_anchor(p, cid, &cerr) != 0 {
		return takeErr(cerr)
	}
	return nil
}

// Dial opens a stream to target ("service@node").
//
// The native dial cannot be interrupted; if ctx ends first, Dial returns
// ctx.Err() and the late connection is closed when it arrives.
func (n *Node) Dial(ctx context.Context, target string) (*Conn, error) {
	p, done, err := n.handle()
	if err != nil {
		return nil, err
	}
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer done()
		t := cstr(target)
		defer freeC(t)
		var fd C.int
		var cerr *C.char
		if C.wired_dial(p, t, &fd, &cerr) != 0 {
			ch <- result{err: takeErr(cerr)}
			return
		}
		c, err := connFromFD(int(fd), Peer{Name: targetNode(target)})
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func targetNode(target string) string {
	for i := len(target) - 1; i >= 0; i-- {
		if target[i] == '@' {
			return target[i+1:]
		}
	}
	return ""
}

// PathKind says how traffic to a peer flows.
type PathKind int

const (
	PathNone PathKind = iota
	PathDirect
	PathRelay
)

func (k PathKind) String() string {
	return [...]string{"none", "direct", "relay"}[k]
}

// Path reports whether traffic to node goes direct or via the relay.
func (n *Node) Path(node string) PathKind {
	p, done, err := n.handle()
	if err != nil {
		return PathNone
	}
	defer done()
	cn := cstr(node)
	defer freeC(cn)
	return PathKind(C.wired_path(p, cn))
}

var wiredHost = regexp.MustCompile(`^([a-z0-9-]+)\.([a-z0-9-]+)\.wired\.?$`)

// HostTarget maps "api.laptop.wired" (optionally with a port) to "api@laptop".
func HostTarget(hostport string) (string, error) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	m := wiredHost.FindStringSubmatch(host)
	if m == nil {
		return "", fmt.Errorf("wired: %q is not a wired host (want service.node.wired)", host)
	}
	return m[1] + "@" + m[2], nil
}

// Transport is an http.RoundTripper that reaches http://service.node.wired/ over Wired.
func (n *Node) Transport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			target, err := HostTarget(addr)
			if err != nil {
				return nil, err
			}
			return n.Dial(ctx, target)
		},
		ForceAttemptHTTP2: false,
	}
}

// HTTPClient is an http.Client using Transport.
func (n *Node) HTTPClient() *http.Client {
	return &http.Client{Transport: n.Transport()}
}

// Close shuts the node down. Pending Accept calls return ErrClosed.
func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.p == nil {
		return nil
	}
	C.wired_node_close(n.p)
	C.wired_node_free(n.p)
	n.p = nil
	return nil
}

// Peer identifies the other end of a stream.
type Peer struct {
	Name string
	ID   string
}

// Addr is a Wired address, "service@node".
type Addr struct {
	Service, Node string
}

func (a Addr) Network() string { return "wired" }
func (a Addr) String() string  { return a.Service + "@" + a.Node }

// Conn is a stream to a peer. It embeds *net.UnixConn, so deadlines and
// CloseWrite (half-close) work.
type Conn struct {
	*net.UnixConn
	peer Peer
}

// Peer is who is on the other end.
func (c *Conn) Peer() Peer { return c.peer }

// RemoteAddr reports the peer's node name.
func (c *Conn) RemoteAddr() net.Addr { return Addr{Node: c.peer.Name} }

func connFromFD(fd int, peer Peer) (*Conn, error) {
	f := os.NewFile(uintptr(fd), "wired")
	defer f.Close() // FileConn dups the descriptor.
	c, err := net.FileConn(f)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("wired: unexpected conn type %T", c)
	}
	return &Conn{UnixConn: uc, peer: peer}, nil
}
