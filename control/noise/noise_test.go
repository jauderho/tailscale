// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noise

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/nettest"
	tsnettest "tailscale.com/net/nettest"
	"tailscale.com/types/key"
)

type inMemoryPSKStore struct {
	sync.Mutex
	keys map[key.Public][]PSK
}

func (s *inMemoryPSKStore) GetPSKs(k key.Public) ([]PSK, error) {
	s.Lock()
	defer s.Unlock()
	if s.keys == nil {
		s.keys = map[key.Public][]PSK{}
	}
	return s.keys[k], nil
}

func (s *inMemoryPSKStore) SetPSKs(k key.Public, psks []PSK) error {
	s.Lock()
	defer s.Unlock()
	if s.keys == nil {
		s.keys = map[key.Public][]PSK{}
	}
	s.keys[k] = psks
	return nil
}

func TestConnect(t *testing.T) {
	s1, s2 := tsnettest.NewConn("noise", 4096)
	controlKey := key.NewPrivate()
	machineKey := key.NewPrivate()
	store := &inMemoryPSKStore{}
	var client, server *Conn
	serverErr := make(chan error, 1)
	serverBytes := make(chan []byte, 1)
	go func() {
		var err error
		server, err = Server(context.Background(), s2, controlKey, store)
		serverErr <- err
		if err != nil {
			return
		}
		defer server.Close()
		bs, err := ioutil.ReadAll(server)
		serverErr <- err
		serverBytes <- bs
	}()
	client, newPSK, err := Client(context.Background(), s1, machineKey, controlKey.Public(), PSK{})
	if err != nil {
		t.Fatalf("client connection failed: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server connection failed: %v", err)
	}

	serverPSKs, err := store.GetPSKs(machineKey.Public())
	if err != nil {
		t.Fatalf("PSK fetch failed: %v", err)
	}
	wantPSKs := []PSK{newPSK, PSK{}}
	if diff := cmp.Diff(serverPSKs, wantPSKs); diff != "" {
		t.Fatalf("Stored PSK mismatch (-got+want):\n%s", diff)
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

func TestNoise(t *testing.T) {
	t.Skip("bork, conn doesn't match the interface contract yet")
	nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
		s1, s2 := tsnettest.NewConn("noise", 4096)
		controlKey := key.NewPrivate()
		machineKey := key.NewPrivate()
		serverErr := make(chan error, 1)
		go func() {
			var err error
			c2, err = Server(context.Background(), s2, controlKey, &inMemoryPSKStore{})
			serverErr <- err
		}()
		c1, _, err = Client(context.Background(), s1, machineKey, controlKey.Public(), PSK{})
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
