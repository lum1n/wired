package wired

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func testAnchor(t *testing.T) *Node {
	t.Helper()
	vps, err := Anchor(AnchorOptions{Name: "vps", BindHost: "127.0.0.1", AnyPorts: true, PublicHost: "127.0.0.1", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vps.Close() })
	return vps
}

func testMember(t *testing.T, name, invite string) *Node {
	t.Helper()
	n, err := Join(JoinOptions{Name: name, Invite: invite, Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

func TestHTTPOverWired(t *testing.T) {
	vps := testAnchor(t)
	laptop := testMember(t, "laptop", vps.Invite())

	ln, err := laptop.Listen("api")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s from laptop%s", r.RemoteAddr, r.URL.Path)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	client := vps.HTTPClient()
	for _, path := range []string{"/a", "/b"} {
		resp, err := client.Get("http://api.laptop.wired" + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if want := "hello @vps from laptop" + path; string(body) != want {
			t.Fatalf("got %q, want %q", body, want)
		}
	}
}

func TestEchoHalfCloseAndPeer(t *testing.T) {
	vps := testAnchor(t)
	a := testMember(t, "a", vps.Invite())
	b := testMember(t, "b", vps.Invite())

	ln, err := b.Listen("echo")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				fmt.Fprintf(c, "%s:%s", c.(*Conn).Peer().Name, data)
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := a.Dial(ctx, "echo@b")
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping"))
	c.CloseWrite()
	got, _ := io.ReadAll(c)
	c.Close()
	if string(got) != "a:ping" {
		t.Fatalf("got %q", got)
	}

	if _, err := a.Dial(ctx, "nope@b"); err == nil {
		t.Fatal("dial to missing service succeeded")
	}

	// Close unblocks a pending Accept.
	done := make(chan struct{})
	go func() {
		ln.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Listener.Close hung")
	}
}

func TestHostTarget(t *testing.T) {
	for in, want := range map[string]string{"api.laptop.wired": "api@laptop", "api.laptop.wired:80": "api@laptop"} {
		if got, err := HostTarget(in); err != nil || got != want {
			t.Errorf("HostTarget(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := HostTarget("example.com:80"); err == nil {
		t.Error("accepted a non-wired host")
	}
}

func TestAllowlistAndRevoke(t *testing.T) {
	vps := testAnchor(t)
	a := testMember(t, "a", vps.Invite())
	b := testMember(t, "b", vps.Invite())

	ln, err := b.ListenAllow("admin", "a")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hi"))
			c.Close()
		}
	}()
	nobody, err := b.ListenAllow("nobody")
	if err != nil {
		t.Fatal(err)
	}
	defer nobody.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := a.Dial(ctx, "admin@b")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := vps.Dial(ctx, "admin@b"); err == nil || !strings.Contains(err.Error(), "Denied") {
		t.Fatalf("vps reached an allowlisted service: %v", err)
	}
	if _, err := a.Dial(ctx, "nobody@b"); err == nil {
		t.Fatal("empty allowlist let a node in")
	}

	if !vps.IsRoot() || a.IsRoot() {
		t.Fatal("IsRoot wrong")
	}
	if _, err := a.Revoke("b"); err == nil {
		t.Fatal("a member revoked a node")
	}
	inv, err := vps.Revoke("a")
	if err != nil || !strings.HasPrefix(inv, "wired1") {
		t.Fatalf("revoke: %q %v", inv, err)
	}
	for _, m := range vps.Members() {
		if m.Name == "a" {
			t.Fatal("revoked node still listed")
		}
	}
	// The revocation reaches b within moments; from then on, a is refused.
	for deadline := time.Now().Add(5 * time.Second); hasMember(b, "a"); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("b never learned of the revocation")
		}
	}
	if _, err := a.Dial(ctx, "admin@b"); err == nil {
		t.Fatal("revoked node could still dial")
	}
	ln.Close()
}

func hasMember(n *Node, name string) bool {
	for _, m := range n.Members() {
		if m.Name == name {
			return true
		}
	}
	return false
}

func TestAddAndRemoveRelay(t *testing.T) {
	vps := testAnchor(t)
	if err := vps.AddRelay("https://relay.example.com"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range vps.Relays() {
		if r.URL == "https://relay.example.com" && !r.Pinned {
			found = true
		}
	}
	if !found {
		t.Fatalf("relay not listed: %+v", vps.Relays())
	}
	if err := vps.RemoveRelay("https://relay.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := vps.AddRelay("ftp://nope"); err == nil {
		t.Fatal("accepted a non-http relay url")
	}
}
