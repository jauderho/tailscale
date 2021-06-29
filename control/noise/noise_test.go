// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"testing"

	"golang.org/x/net/nettest"
	tsnettest "tailscale.com/net/nettest"
	"tailscale.com/types/key"
)

func TestMessageSize(t *testing.T) {
	// This test is a regression guard against someone looking at
	// maxCiphertextSize, going "huh, we could be more efficient if it
	// were larger, and accidentally violating the Noise spec. Do not
	// change this max value, it's a deliberate limitation of the
	// cryptographic protocol we use (see Section 3 "Message Format"
	// of the Noise spec).
	const max = 65535
	if maxCiphertextSize > max {
		t.Fatalf("max ciphertext size is %d, which is larger than the maximum noise message size %d", maxCiphertextSize, max)
	}
}

func TestConnect(t *testing.T) {
	s1, s2 := tsnettest.NewConn("noise", 4096)
	controlKey := key.NewPrivate()
	machineKey := key.NewPrivate()
	var client, server *Conn
	serverErr := make(chan error, 1)
	serverBytes := make(chan []byte, 1)
	go func() {
		var err error
		server, err = Server(context.Background(), s2, controlKey)
		serverErr <- err
		if err != nil {
			return
		}
		defer server.Close()
		bs, err := ioutil.ReadAll(server)
		serverErr <- err
		serverBytes <- bs
	}()
	client, err := Client(context.Background(), s1, machineKey, controlKey.Public())
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server connection failed: %v", err)
	}

	ch, sh := client.HandshakeHash(), server.HandshakeHash()
	if !bytes.Equal(ch[:], sh[:]) {
		t.Fatal("mismatched handshake hashes on client and server")
	}

	cpk, spk := client.Peer(), server.Peer()
	controlKeyPub := controlKey.Public()
	if !bytes.Equal(cpk[:], controlKeyPub[:]) {
		t.Fatal("client peer isn't controlKey")
	}
	machineKeyPub := machineKey.Public()
	if !bytes.Equal(spk[:], machineKeyPub[:]) {
		t.Fatal("server peer isn't machineKey")
	}

	if _, err := io.WriteString(client, "test"); err != nil {
		t.Fatalf("client write failed: %v", err)
	}
	client.Close()

	if err := <-serverErr; err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if bs := <-serverBytes; string(bs) != "test" {
		t.Fatal("wrong content received")
	}
}

func TestConn(t *testing.T) {
	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		s1, s2 := tsnettest.NewConn("noise", 4096)
		controlKey := key.NewPrivate()
		machineKey := key.NewPrivate()
		serverErr := make(chan error, 1)
		go func() {
			var err error
			c2, err = Server(context.Background(), s2, controlKey)
			serverErr <- err
		}()
		c1, err = Client(context.Background(), s1, machineKey, controlKey.Public())
		if err != nil {
			s1.Close()
			s2.Close()
			return nil, nil, nil, fmt.Errorf("connecting client: %w", err)
		}
		if err := <-serverErr; err != nil {
			c1.Close()
			s1.Close()
			s2.Close()
			return nil, nil, nil, fmt.Errorf("connecting server: %w", err)
		}
		return c1, c2, func() {
			c1.Close()
			c2.Close()
		}, nil
	})
}
