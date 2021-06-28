// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package noise implements the base transport of the Tailscale 2021
// control protocol.
//
// The base transport implements Noise IKpsk1, instantiated with
// Curve25519, ChaCha20Poly1305 and BLAKE2s.
//
// The PSK is initially zero, and ratchets to a new value after each
// successful handshake. The PSK ratchet enables detection of machine
// key cloning.
package noise

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"tailscale.com/types/key"
)

const (
	protocolName     = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s"
	invalidNonce     = ^uint64(0)
	maxMessageSize   = 65535 // max allowed size of a Noise message
	maxPlaintextSize = maxMessageSize - poly1305.TagSize
)

// Initiate executes an IKpsk1 handshake from the initiator's
// perspective (i.e. the client talking to Control), returning the
// resulting Noise connection.
func Initiate(ctx context.Context, conn net.Conn, machineKey key.Private, controlKey key.Public, psk [32]byte) (*Conn, error) {
	var s symmetricState
	s.Initialize()

	// <- s
	// ...
	s.MixHash(controlKey[:])

	var init initiationMessage
	// -> e, es, s, ss, psk
	machineEphemeral := key.NewPrivate()
	machineEphemeralPub := machineEphemeral.Public()
	copy(init.MachineEphemeralPub(), machineEphemeralPub[:])
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(machineEphemeral, controlKey); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	machineKeyPub := machineKey.Public()
	copy(init.MachinePub(), s.EncryptAndHash(machineKeyPub[:]))
	if err := s.MixDH(machineKey, controlKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	s.MixKeyAndHash(psk)
	copy(init.Tag(), s.EncryptAndHash(nil))

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting connection deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}
	if _, err := conn.Write(init[:]); err != nil {
		return nil, fmt.Errorf("writing initiation: %w", err)
	}

	// <- e, ee, se
	var resp responseMessage
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	re, err := s.DecryptAndHash(resp.ControlEphemeralPub())
	if err != nil {
		return nil, fmt.Errorf("decrypting control ephemeral key: %w", err)
	}
	var controlEphemeralPub key.Public
	copy(controlEphemeralPub[:], re)
	if err := s.MixDH(machineEphemeral, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(machineKey, controlEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	if _, err := s.DecryptAndHash(resp.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting payload: %w", err)
	}

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	return &Conn{
		conn:          conn,
		handshakeHash: s.h,
		tx:            c1,
		rx:            c2,
	}, nil
}

type PSKStore interface {
	GetPSKs(machineKey key.Public) ([][32]byte, error)
	SetPSKs(machineKey key.Public, psks [][32]byte) error
}

// Respond executes an IKpsk1 handshake from the responder's
// perspective (i.e. control talking to a client), returning the
// resulting Noise connection.
func Respond(ctx context.Context, conn net.Conn, controlKey key.Private, rstore PSKStore) (*Conn, error) {
	var s symmetricState
	s.Initialize()

	// <- s
	// ...
	controlKeyPub := controlKey.Public()
	s.MixHash(controlKeyPub[:])

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting connection deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	// -> e, es, s, ss, psk
	var init initiationMessage
	if _, err := io.ReadFull(conn, init[:]); err != nil {
		return nil, fmt.Errorf("reading initiation: %w", err)
	}

	var machineEphemeralPub key.Public
	copy(machineEphemeralPub[:], init.MachineEphemeralPub())
	s.MixHash(machineEphemeralPub[:])
	if err := s.MixDH(controlKey, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
	var machineKey key.Public
	rs, err := s.DecryptAndHash(init.MachinePub())
	if err != nil {
		return nil, fmt.Errorf("decrypting machine key: %w", err)
	}
	copy(machineKey[:], rs)
	if err := s.MixDH(controlKey, machineKey); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}
	psks, err := rstore.GetPSKs(machineKey)
	if err != nil {
		return nil, fmt.Errorf("getting PSK: %w", err)
	}
	// We have to try several PSK values. If we don't get it right
	// the first time, we need to reset to this step in the handshake
	// processing.
	backupState := s
	var correctPSK *[32]byte
	for _, psk := range psks {
		s.MixKeyAndHash(psk)
		if _, err := s.DecryptAndHash(init.Tag()); err != nil {
			// Likely the wrong PSK, try another.
			s = backupState
			continue
		}
		correctPSK = &psk
		break
	}
	if correctPSK == nil {
		// None of the PSKs we know of match this handshake. This very
		// likely means the machine key was cloned.
		// TODO: we should return a specific "machine key cloned"
		// error here, so Control can do remediation.
		return nil, errors.New("invalid PSK")
	}

	// <- e, ee, se
	var resp responseMessage
	controlEphemeral := key.NewPrivate()
	controlEphemeralPub := controlEphemeral.Public()
	copy(resp.ControlEphemeralPub(), controlEphemeralPub[:])
	if err := s.MixDH(controlEphemeral, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(controlEphemeral, machineKey); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	copy(resp.Tag(), s.EncryptAndHash(nil))

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}
	ret := &Conn{
		conn:          conn,
		handshakeHash: s.h,
		tx:            c2,
		rx:            c1,
	}

	// Handshake is complete, so we create a new ratchet value for the
	// next connection. We also remember the ratchet value used by the
	// current connection, to allow for the client crashing before it
	// persists the new PSK.
	newPSKs := [][32]byte{s.h, *correctPSK}
	if err := rstore.SetPSKs(machineKey, newPSKs); err != nil {
		// Failed to store new values, can't safely complete handshake.
		return nil, fmt.Errorf("saving new ratchets: %w", err)
	}

	if _, err := conn.Write(resp[:]); err != nil {
		return nil, err
	}

	return ret, nil
}

// initiationMessage is the Noise protocol message sent from a client
// machine to a control server.
type initiationMessage [96]byte

func (m *initiationMessage) MachineEphemeralPub() []byte { return m[:32] }
func (m *initiationMessage) MachinePub() []byte          { return m[32:80] }
func (m *initiationMessage) Tag() []byte                 { return m[80:] }

// responseMessage is the Noise protocol message sent from a control
// server to a client machine.
type responseMessage [64]byte

func (m *responseMessage) ControlEphemeralPub() []byte { return m[:48] }
func (m *responseMessage) Tag() []byte                 { return m[48:] }

// symmetricState is the SymmetricState object from the Noise protocol
// spec. It contains all the symmetric cipher state of an in-flight
// handshake. Field names match the variable names in the spec.
type symmetricState struct {
	h  [blake2s.Size]byte
	ck [blake2s.Size]byte

	k [chp.KeySize]byte
	n uint64

	mixer hash.Hash // for updating h
}

// Initialize sets s to the initial handshake state, prior to
// processing any Noise messages.
func (s *symmetricState) Initialize() {
	if s.mixer != nil {
		panic("symmetricState cannot be reused")
	}
	s.h = blake2s.Sum256([]byte(protocolName))
	s.ck = s.h
	s.k = [chp.KeySize]byte{}
	s.n = invalidNonce
	s.mixer = newBLAKE2s()
	// Mix in an empty prologue.
	s.MixHash(nil)
}

// MixHash updates s.h to be BLAKE2s(s.h || data), where || is
// concatenation.
func (s *symmetricState) MixHash(data []byte) {
	s.mixer.Reset()
	s.mixer.Write(s.h[:])
	s.mixer.Write(data)
	s.mixer.Sum(s.h[:0]) // TODO: check this actually updates s.h correctly...
}

// MixDH updates s.ck and s.k with the result of X25519(priv, pub).
//
// MixDH corresponds to MixKey(X25519(...))) in the spec. Implementing
// it as a single function allows for strongly-typed arguments that
// reduce the risk of error in the caller (e.g. invoking X25519 with
// two private keys, or two public keys), and thus producing the wrong
// calculation.
func (s *symmetricState) MixDH(priv key.Private, pub key.Public) error {
	keyData, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return fmt.Errorf("computing X25519: %w", err)
	}

	r := hkdf.New(newBLAKE2s, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return fmt.Errorf("computing HKDF: %w", err)
	}
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		return fmt.Errorf("computing HKDF: %w", err)
	}
	s.n = 0
	return nil
}

// MixKeyAndHash updates s.k, s.ck and s.h with the value of psk.
func (s *symmetricState) MixKeyAndHash(psk [32]byte) error {
	r := hkdf.New(newBLAKE2s, psk[:], s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return fmt.Errorf("computing HKDF: %w", err)
	}
	var temph [blake2s.Size]byte
	if _, err := io.ReadFull(r, temph[:]); err != nil {
		return fmt.Errorf("computing HKDF: %w", err)
	}
	s.MixHash(temph[:])
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		return fmt.Errorf("computing HKDF: %w", err)
	}
	s.n = 0
	return nil
}

// EncryptAndHash encrypts the given plaintext using the current s.k,
// mixes the ciphertext into s.h, and returns the ciphertext.
func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	if s.n == invalidNonce {
		// Noise in general permits writing "ciphertext" without a
		// key, but in IKpsk1 it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret := aead.Seal(nil, nonce[:], plaintext, s.h[:])
	s.MixHash(ret)
	return ret
}

// DecryptAndHash decrypts the given ciphertext using the current
// s.k. If decryption is successful, it mixes the ciphertext into s.h
// and returns the plaintext.
func (s *symmetricState) DecryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.n == invalidNonce {
		// Noise in general permits "ciphertext" without a key, but in
		// IKpsk1 it cannot happen.
		panic("attempted encryption with uninitialized key")
	}
	aead := newCHP(s.k)
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret, err := aead.Open(nil, nonce[:], ciphertext, s.h[:])
	if err != nil {
		return nil, err
	}
	s.MixHash(ciphertext)
	return ret, nil
}

// Split returns two ChaCha20Poly1305 ciphers with keys derives from
// the current handshake state. Methods on s must not be used again
// after calling Split().
func (s *symmetricState) Split() (c1, c2 cipher.AEAD, err error) {
	var k1, k2 [chp.KeySize]byte
	r := hkdf.New(newBLAKE2s, nil, s.ck[:], nil)
	if _, err := io.ReadFull(r, k1[:]); err != nil {
		return nil, nil, fmt.Errorf("computing HKDF: %w", err)
	}
	if _, err := io.ReadFull(r, k2[:]); err != nil {
		return nil, nil, fmt.Errorf("computing HKDF: %w", err)
	}
	c1, err = chp.New(k1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD: %w", err)
	}
	c2, err = chp.New(k2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD: %w", err)
	}
	return c1, c2, nil
}

// newBLAKE2s returns a hash.Hash implementing BLAKE2s, or panics on
// error.
func newBLAKE2s() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		// Should never happen, errors only happen when using BLAKE2s
		// in MAC mode with a key.
		panic(fmt.Sprintf("blake2s construction: %v", err))
	}
	return h
}

// newCHP returns a cipher.AEAD implementing ChaCha20Poly1305, or
// panics on error.
func newCHP(key [chp.KeySize]byte) cipher.AEAD {
	aead, err := chp.New(key[:])
	if err != nil {
		// Can only happen if we passed a key of the wrong length. The
		// function signature prevents that.
		panic(fmt.Sprintf("chacha20poly1305 construction: %v", err))
	}
	return aead
}

// A Conn represents a secured Noise connection. It implements the
// net.Conn interface.
type Conn struct {
	conn net.Conn
	// TODO: reuse buffers to avoid allocations. Currently allocates
	// fresh for every packet.
	buf []byte // previously decrypted bytes

	peer          key.Public
	handshakeHash [blake2s.Size]byte

	tx  cipher.AEAD
	txN uint64
	rx  cipher.AEAD
	rxN uint64
}

// HandshakeHash returns the Noise handshake hash for the connection,
// which can be used to bind other messages to this connection
// (i.e. to ensure that the message wasn't replayed from a different
// connection).
func (c *Conn) HandshakeHash() [blake2s.Size]byte {
	return c.handshakeHash
}

// Peer returns the peer's long-term public key.
func (c *Conn) Peer() key.Public {
	return c.peer
}

// refill reads one Noise message and decrypts it into c.buf.
func (c *Conn) refill() error {
	if c.rxN == invalidNonce {
		// Received 2^64-1 messages on this cipher state. Connection
		// is no longer usable.
		return net.ErrClosed
	}
	var sz [2]byte
	if _, err := io.ReadFull(c.conn, sz[:]); err != nil {
		return err
	}

	payloadLen := binary.BigEndian.Uint16(sz[:])
	ciphertext := make([]byte, payloadLen) // TODO: reuse bufs
	if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
		return err
	}
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], c.rxN)
	c.rxN++
	plaintext, err := c.rx.Open(ciphertext[:0], nonce[:], ciphertext, nil)
	if err != nil {
		return err
	}

	c.buf = plaintext
	return nil
}

// scorch deletes the cipher state for c. After scorching, the
// connection can no longer receive or transmit data.
func (c *Conn) scorch() {
	c.tx = nil
	c.txN = invalidNonce
	c.rx = nil
	c.rxN = invalidNonce
}

func (c *Conn) Read(bs []byte) (int, error) {
	if c.rx == nil {
		return 0, net.ErrClosed
	}
	if c.rxN == invalidNonce {
		// Somehow sent 2^64-1 messages on this cipher
		// state. Connection is no longer usable.
		c.scorch()
		return 0, net.ErrClosed
	}
	if len(c.buf) == 0 {
		if err := c.refill(); err != nil {
			c.scorch()
			return 0, err
		}
	}
	n := copy(bs, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *Conn) Write(bs []byte) (int, error) {
	if c.tx == nil {
		return 0, net.ErrClosed
	}

	var sent int
	for len(bs) > 0 {
		if c.rxN == invalidNonce {
			// Somehow sent 2^64-1 messages on this cipher
			// state. Connection is no longer usable.
			c.scorch()
			return 0, net.ErrClosed
		}

		toSend := bs
		if len(toSend) > maxPlaintextSize {
			toSend = bs[:maxPlaintextSize]
		}
		bs = bs[len(toSend):]

		// TODO: reuse buffers, be less wasteful.
		ciphertext := make([]byte, len(toSend)+poly1305.TagSize+2)
		binary.BigEndian.PutUint16(ciphertext[:2], uint16(len(ciphertext)-2))
		var nonce [chp.NonceSize]byte
		binary.BigEndian.PutUint64(nonce[4:], c.txN)
		c.txN++
		c.tx.Seal(ciphertext[:2], nonce[:], toSend, nil)
		if _, err := c.conn.Write(ciphertext); err != nil {
			c.scorch()
			return sent, err
		}
		sent += len(toSend)
	}
	return sent, nil
}

func (c *Conn) Close() error {
	c.scorch()
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
