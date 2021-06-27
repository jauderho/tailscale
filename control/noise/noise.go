// Package noise implements the Noise IKpsk1 handshake, instantiated
// with Curve25519, ChaCha20Poly1305, and BLAKE2s. It is used by
// Taislcale's 2021 control protocol.
package noise

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/aead/chacha20poly1305"
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
		h   = blake2s.Sum256([]byte(protocolName))
		ck  = h
		k   [chacha20poly1305.KeySize]byte
		n   uint64
	)

	mixHash := func(data []byte) {
		hh := blake2s.New()
		hh.Write(h[:])
		hh.Write(data)
		hh.Sum(h[:0])
	}
	mixKey := func(keyData []byte) {
		r := hkdf.New(blake2s.New, keyData, ck[:])
		if _, err := io.ReadFull(r, ck[:]); err != nil {
			// This can only happen if we exhaust HKDF's entropy,
			// which would take reading out 256 keys. We only read out
			// 2.
			panic(fmt.Sprintf("HKDF failed: %v", err))
		}
		if _, err := io.ReadFull(r, k[:]); err != nil {
			panic(fmt.Sprintf("HKDF failed: %v", err))
		}
		n = 0
	}

	mixHash(nil) // empty prologue, but we have to mix.

	// <- s
	// ...
	mixHash(rs[:])

	// -> e, es, s, ss, psk
	e = key.NewPrivate()
	copy(msg[:], e.Public()[:])
	mixHash(e.Public()[:])

	es, err := curve25519.X25519(e[:], rs[:])
	if err != nil {
		return nil, fmt.Errorf("computing es: %w", err)
	}
}

func hkdf2(ck, km []byte) ([blake2s.Size]byte, [blake2s.Size]byte) {

}
