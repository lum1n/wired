package wired

/*
#include <stdlib.h>
#include "wired.h"
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Listener accepts streams for one service. It implements net.Listener, so
// http.Serve(ln, handler) works.
type Listener struct {
	node    *Node
	service string

	mu        sync.Mutex
	p         *C.WiredListener
	accepting sync.WaitGroup
	closed    bool
}

// Listen accepts streams for service from any member.
func (n *Node) Listen(service string) (*Listener, error) {
	return n.listen(service, nil)
}

// ListenAllow accepts streams for service only from the named nodes.
func (n *Node) ListenAllow(service string, allow ...string) (*Listener, error) {
	for _, a := range allow {
		if a == "" || strings.Contains(a, ",") {
			return nil, fmt.Errorf("wired: invalid node name %q in allowlist", a)
		}
	}
	// A variadic call with no names passes nil, which would mean "everyone".
	if allow == nil {
		allow = []string{}
	}
	return n.listen(service, allow)
}

func (n *Node) listen(service string, allow []string) (*Listener, error) {
	p, done, err := n.handle()
	if err != nil {
		return nil, err
	}
	defer done()
	s := cstr(service)
	defer freeC(s)
	var a *C.char
	if allow != nil {
		// A non-NULL empty string means "nobody".
		a = C.CString(strings.Join(allow, ","))
		defer freeC(a)
	}
	var lp *C.WiredListener
	var cerr *C.char
	if C.wired_listen(p, s, a, &lp, &cerr) != 0 {
		return nil, takeErr(cerr)
	}
	return &Listener{node: n, service: service, p: lp}, nil
}

// Accept waits for the next stream. Returned conns are *Conn.
func (l *Listener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	p := l.p
	l.accepting.Add(1)
	l.mu.Unlock()
	defer l.accepting.Done()

	var fd C.int
	var name, id, cerr *C.char
	switch C.wired_accept(p, &fd, &name, &id, &cerr) {
	case 0:
		return connFromFD(int(fd), Peer{Name: goString(name), ID: goString(id)})
	case 1:
		return nil, ErrClosed
	default:
		return nil, takeErr(cerr)
	}
}

// Close stops accepting and unregisters the service.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	p := l.p
	l.mu.Unlock()

	C.wired_listener_close(p)
	l.accepting.Wait()
	C.wired_listener_free(p)
	return nil
}

// Addr is "service@node".
func (l *Listener) Addr() net.Addr {
	return Addr{Service: l.service, Node: l.node.Name()}
}
