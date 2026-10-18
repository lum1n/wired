// Interop helper: `wired-echo serve <name>` | `wired-echo dial <name> <node>` (uses WIRED_INVITE).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	wired "github.com/lum1n/wired/bindings/go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: wired-echo serve <name> | dial <name> <node>")
		os.Exit(2)
	}
	node, err := wired.Join(wired.JoinOptions{Name: os.Args[2], Ephemeral: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer node.Close()

	switch os.Args[1] {
	case "serve":
		ln, err := node.Listen("echo")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "serving echo@%s\n", os.Args[2])
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data, _ := io.ReadAll(c)
				c.Write(data)
			}()
		}
	case "dial":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		c, err := node.Dial(ctx, "echo@"+os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		c.Write([]byte("ping"))
		c.CloseWrite()
		got, _ := io.ReadAll(c)
		c.Close()
		if string(got) != "ping" {
			fmt.Printf("bad echo: %q\n", got)
			os.Exit(1)
		}
		fmt.Println("roundtrip=ok")
	}
}
