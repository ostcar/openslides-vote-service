package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"

	"github.com/ostcar/eciesgo"
)

// Crypto implements all cryptographic functions needed for the decrypt service.
type Crypto struct {
	mainKey ecdsa.PrivateKey
	random  io.Reader
}

// New initializes a Crypto object with a main key and a random source.
func New(mainKey []byte, random io.Reader) Crypto {
	return Crypto{
		mainKey: mainFromBytes(mainKey),
		random:  random,
	}
}

func mainFromBytes(priv []byte) ecdsa.PrivateKey {
	curve := elliptic.P521()
	x, y := curve.ScalarBaseMult(priv)

	return ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(priv),
	}
}

// CreatePollKey creates a new keypair for a poll.
func (c Crypto) CreatePollKey() ([]byte, error) {
	key, err := eciesgo.GenerateKey(c.random)
	if err != nil {
		return nil, fmt.Errorf("generating eciesgo key: %w", err)
	}

	return key.Bytes(), nil
}

// PublicPollKey returns the public poll key and the signature for a given key.
func (c Crypto) PublicPollKey(key []byte) (pubKey []byte, pubKeySig []byte, err error) {
	pubKey = eciesgo.NewPrivateKeyFromBytes(key).PublicKey.Bytes(true)

	// TODO: either make sure pubKey is small enough or hash it.
	sig, err := ecdsa.SignASN1(c.random, &c.mainKey, pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing key: %w", err)
	}

	return pubKey, sig, nil
}

// Decrypt returned the plaintext from value using the key.
func (c Crypto) Decrypt(key []byte, value []byte) ([]byte, error) {
	pollKey := eciesgo.NewPrivateKeyFromBytes(key)

	decrypted, err := eciesgo.Decrypt(pollKey, value)
	if err != nil {
		return nil, fmt.Errorf("ecies decrypt: %w", err)
	}

	return decrypted, nil
}

// Sign returns the signature for the given data.
func (c Crypto) Sign(value []byte) ([]byte, error) {
	hasher := sha512.New()
	hash := hasher.Sum(value)

	sig, err := ecdsa.SignASN1(c.random, &c.mainKey, hash)
	if err != nil {
		return nil, fmt.Errorf("signing data: %w", err)
	}

	return sig, nil
}
