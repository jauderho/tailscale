// Package noise implements the Noise IKpsk1 handshake, instantiated
// with Curve25519, ChaCha20Poly1305, and BLAKE2s. It is used by
// Taislcale's 2021 control protocol.
package noise

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	chp "github.com/aead/chacha20poly1305"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"tailscale.com/types/key"
)

type PSK [32]byte

const (
	keySize          = 32
	encryptedKeySize = 32 + 8 // ciphertext + poly1305 tag
	protocolName     = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s"
)

type symmetricState struct {
	h            [blake2s.Size]byte
	ck           [blake2s.Size]byte
	k            [chp.KeySize]byte
	kInitialized bool
	n            uint64
}

func (s *symmetricState) Initialize() {
	s.h = blake2s.Sum(protocolName)
	s.ck = h
	s.k = [chp.KeySize]byte{}
	s.kInitialized = false
	s.n = 0
}

func (s *symmetricState) MixKey(keyData []byte) {
	r := hkdf.New(blake2s.New, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		// HKDF only fails to read if we try to read 256 keys out. We
		// only read out 2.
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}
	s.kInitialized = true
	s.n = 0
}

func (s *symmetricState) MixKeyAndHash(keyData []byte) {
	r := hkdf.New(blake2s.New, keyData, s.ck[:], nil)
	if _, err := io.ReadFull(r, s.ck[:]); err != nil {
		// HKDF only fails to read if we try to read 256 keys out. We
		// only read out 2.
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}
	var temph [blake2s.KeySize]byte
	if _, err := io.ReadFull(r, temph[:]); err != nil {
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}
	st.MixHash(temph[:])
	if _, err := io.ReadFull(r, s.k[:]); err != nil {
		panic(fmt.Sprintf("HKDF failed: %v", err))
	}
	s.kInitialized = true
	s.n = 0
}

// MixDH is MixKey(X25519(sec, pub))
func (s *symmetricState) MixDH(sec key.Private, pub key.Public) error {
	km, err := curve25519.X25519(sec[:], pub[:])
	if err != nil {
		return err
	}
	s.MixKey(km)
}

func (s *symmetricState) MixHash(data []byte) {
	h := blake2s.New()
	h.Write(s.h[:])
	h.Write(data)
	h.Sum(s.h[:0])
}

func (s *symmetricState) EncryptAndHash(plaintext []byte) []byte {
	if !s.kInitialized {
		s.MixHash(plaintext)
		return plaintext
	}

	aead := chp.New(s.k[:])
	var nonce [chp.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], s.n)
	s.n++
	ret := aead.Seal(nil, nonce[:], plaintext, s.h[:])
	st.MixHash(ret)
	return ret
}

// Initiate runs the IKpsk1 handshake from the initiator's perspective
// (i.e. the client talking to Control). If the handshake is
// successful, returns a wrapper net.Conn that implements the
// transport encryption. Returns an error and closes conn if the
// handshake fails, to avoid any chance of accidental unauthenticated
// use.
func Initiate(ctx context.Context, conn net.Conn, machineKey key.Private, controlKey key.Public, ratchet PSK) (net.Conn, error) {
	// The state variables are deliberately named to match the Noise
	// specification, to make it easier to verify the implementation
	// by following the spec in parallel.
	var (
		s   = machineKey
		rs  = controlKey
		e   key.Private
		re  key.Public
		psk = ratchet
		st  symmetricState
	)

	st.Initialize()
	st.MixHash(nil) // empty prologue, but we have to mix.

	// <- s
	// ...
	st.MixHash(rs[:])

	var msg bytes.Buffer
	// -> e, es, s, ss, psk
	e = key.NewPrivate()
	msg.Write(e.Public()[:])
	st.MixHash(e.Public()[:])

	if err := st.MixDH(e, rs); err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}

	msg.Write(st.EncryptAndHash(s[:]))

	if err := st.MixDH(s, rs); err != nil {
		return nil, fmt.Errorf("computing ss: %w", err)
	}

	st.MixKeyAndHash(psk[:])

	return nil, nil
}
