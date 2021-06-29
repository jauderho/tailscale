// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package noise implements the base transport of the Tailscale 2021
// control protocol.
//
// The base transport implements Noise IK, instantiated with
// Curve25519, ChaCha20Poly1305 and BLAKE2s.
package noise

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	chp "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
	"tailscale.com/types/key"
)

const (
	protocolName      = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	invalidNonce      = ^uint64(0)
	maxPlaintextSize  = 4096
	maxCiphertextSize = maxPlaintextSize + poly1305.TagSize
	maxPacketSize     = maxCiphertextSize + 2 // ciphertext + length header
)

// Client initiates a Noise client handshake, returning the resulting
// Noise connection.
//
// The context deadline, if any, covers the entire handshaking
// process.
func Client(ctx context.Context, conn net.Conn, machineKey key.Private, controlKey key.Public) (*Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting conn deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	var s symmetricState
	s.Initialize()

	// <- s
	// ...
	s.MixHash(controlKey[:])

	var init initiationMessage
	// -> e, es, s, ss
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
	copy(init.Tag(), s.EncryptAndHash(nil)) // empty message payload

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
	copy(controlEphemeralPub[:], re) // TODO: change DecryptAndHash signature to avoid this copy
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
		peer:          controlKey,
		handshakeHash: s.h,
		tx:            c1,
		rx:            c2,
	}, nil
}

// Server initiates a Noise server handshake, returning the resulting
// Noise connection.
//
// The context deadline, if any, covers the entire handshaking
// process.
func Server(ctx context.Context, conn net.Conn, controlKey key.Private) (*Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting conn deadline: %w", err)
		}
		defer func() {
			conn.SetDeadline(time.Time{})
		}()
	}

	var s symmetricState
	s.Initialize()

	// <- s
	// ...
	controlKeyPub := controlKey.Public()
	s.MixHash(controlKeyPub[:])

	// -> e, es, s, ss
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
	if _, err := s.DecryptAndHash(init.Tag()); err != nil {
		return nil, fmt.Errorf("decrypting initiation tag: %w", err)
	}

	// <- e, ee, se
	var resp responseMessage
	controlEphemeral := key.NewPrivate()
	controlEphemeralPub := controlEphemeral.Public()
	copy(resp.ControlEphemeralPub(), s.EncryptAndHash(controlEphemeralPub[:]))
	if err := s.MixDH(controlEphemeral, machineEphemeralPub); err != nil {
		return nil, fmt.Errorf("computing ee: %w", err)
	}
	if err := s.MixDH(controlEphemeral, machineKey); err != nil {
		return nil, fmt.Errorf("computing se: %w", err)
	}
	copy(resp.Tag(), s.EncryptAndHash(nil)) // empty message payload

	c1, c2, err := s.Split()
	if err != nil {
		return nil, fmt.Errorf("finalizing handshake: %w", err)
	}

	if _, err := conn.Write(resp[:]); err != nil {
		return nil, err
	}

	return &Conn{
		conn:          conn,
		peer:          machineKey,
		handshakeHash: s.h,
		tx:            c2,
		rx:            c1,
	}, nil
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
	// TODO(danderson): check that this operation is correct. The docs
	// for X25519 say that the 2nd arg must be either Basepoint or the
	// output of another X25519 call.
	//
	// I think this is correct, because pub is the result of a
	// ScalarBaseMult on the private key, and our private key
	// generation code clamps keys to avoid low order points. I
	// believe that makes pub equivalent to the output of
	// X25519(privateKey, Basepoint), and so the contract is
	// respected.
	keyData, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return fmt.Errorf("computing X25519: %w", err)
	}

	r := hkdf.New(newBLAKE2s, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		return fmt.Errorf("extracting ck: %w", err)
	}
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		return fmt.Errorf("extracting k: %w", err)
	}
	s.n = 0
	return nil
}

// EncryptAndHash encrypts the given plaintext using the current s.k,
// mixes the ciphertext into s.h, and returns the ciphertext.
func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	if s.n == invalidNonce {
		// Noise in general permits writing "ciphertext" without a
		// key, but in IK it cannot happen.
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
		// IK it cannot happen.
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
		return nil, nil, fmt.Errorf("extracting k1: %w", err)
	}
	if _, err := io.ReadFull(r, k2[:]); err != nil {
		return nil, nil, fmt.Errorf("extracting k2: %w", err)
	}
	c1, err = chp.New(k1[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD c1: %w", err)
	}
	c2, err = chp.New(k2[:])
	if err != nil {
		return nil, nil, fmt.Errorf("constructing AEAD c2: %w", err)
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
	conn          net.Conn
	peer          key.Public
	handshakeHash [blake2s.Size]byte

	readMu      sync.Mutex
	rx          cipher.AEAD
	rxNonce     [chp.NonceSize]byte
	rxBuf       [maxPacketSize]byte
	rxN         int    // number of valid bytes in rxBuf
	rxPlaintext []byte // slice into rxBuf of decrypted bytes

	writeMu sync.Mutex
	tx      cipher.AEAD
	txNonce [chp.NonceSize]byte
	txBuf   [maxPacketSize]byte
	txErr   error // records the first write error for all future calls
}

// 2b length, Nb payload

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

func (c *Conn) readNLocked(total int) ([]byte, error) {
	if total <= c.rxN {
		return c.rxBuf[:c.rxN], nil
	}

	n, err := io.ReadFull(c.conn, c.rxBuf[c.rxN:total])
	c.rxN += n
	return c.rxBuf[:c.rxN], err
}

func validNonce(nonce []byte) bool {
	return binary.BigEndian.Uint32(nonce[:4]) == 0 && binary.BigEndian.Uint64(nonce[4:]) != invalidNonce
}

func incrNonce(nonce []byte) {
	if !validNonce(nonce) { // Last ditch attempt to prevent accidental nonce reuse.
		panic("cannot increment invalidNonce")
	}
	binary.BigEndian.PutUint64(nonce[4:], 1+binary.BigEndian.Uint64(nonce[4:]))
}

// refill reads one Noise message and decrypts it into c.rxBuf.
func (c *Conn) refillLocked() error {
	if !validNonce(c.rxNonce[:]) {
		// Received 2^64-1 messages on this cipher state. Connection
		// is no longer usable.
		return net.ErrClosed
	}

	bs, err := c.readNLocked(2)
	if err != nil {
		return err
	}
	payloadLen := int(binary.BigEndian.Uint16(bs[:2]))
	bs, err = c.readNLocked(2 + payloadLen)
	if err != nil {
		return err
	}

	c.rxPlaintext, err = c.rx.Open(bs[2:2], c.rxNonce[:], bs[2:], nil)
	if err != nil {
		// Decryption error, must torch the crypto state. TODO
		return err
	}
	incrNonce(c.rxNonce[:])
	c.rxN = 0 // So the next refill starts reading the next frame.
	return nil
}

func (c *Conn) Read(bs []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if c.rx == nil {
		return 0, net.ErrClosed
	}
	// Loop to handle receiving a zero-byte Noise message. Just skip
	// over it and keep decrypting until we find some bytes.
	for len(c.rxPlaintext) == 0 {
		if err := c.refillLocked(); err != nil {
			return 0, err
		}
	}
	n := copy(bs, c.rxPlaintext)
	c.rxPlaintext = c.rxPlaintext[n:]
	return n, nil
}

func (c *Conn) Write(bs []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.txErr != nil {
		return 0, c.txErr
	}
	defer func() {
		if err != nil {
			c.txErr = err
		}
	}()

	if c.tx == nil {
		return 0, net.ErrClosed
	}

	var sent int
	for len(bs) > 0 {
		if !validNonce(c.txNonce[:]) {
			// Somehow sent 2^64-1 messages on this cipher
			// state. Can no longer write.
			c.tx = nil
			return 0, net.ErrClosed
		}

		toSend := bs
		if len(toSend) > maxPlaintextSize {
			toSend = bs[:maxPlaintextSize]
		}
		bs = bs[len(toSend):]

		binary.BigEndian.PutUint16(c.txBuf[:2], uint16(len(toSend)+poly1305.TagSize))
		ciphertext := c.tx.Seal(c.txBuf[:2], c.txNonce[:], toSend, nil)
		incrNonce(c.txNonce[:])
		if _, err := c.conn.Write(ciphertext); err != nil {
			c.tx = nil
			return sent, err
		}
		sent += len(toSend)
	}
	return sent, nil
}

func (c *Conn) Close() error {
	closeErr := c.conn.Close() // unblocks any waiting reads or writes
	c.readMu.Lock()
	c.rx = nil
	c.readMu.Unlock()
	c.writeMu.Lock()
	c.tx = nil
	c.writeMu.Unlock()
	return closeErr
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
