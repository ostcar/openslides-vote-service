package crypto

import (
	"bytes"
	"fmt"
	"io"
)

// Crypto implements all cryptographic functions needed for the decrypt service.
type Crypto struct {
	mainKey []byte
	random  io.Reader
}

// New initializes a Crypto object with a main key and a random source.
func New(mainKey []byte, random io.Reader) Crypto {
	return Crypto{
		mainKey: mainKey,
		random:  random,
	}
}

// PublicMainKey returns the public main key and the signature of the key.
func (c Crypto) PublicMainKey(key []byte) (pubKey []byte, err error) {
	return []byte("publicMainKey"), nil
}

// CreatePollKey creates a new keypair for a poll.
func (c Crypto) CreatePollKey() (key []byte, err error) {
	return []byte("secredPollKey"), nil
}

// PublicPollKey returns the public poll key and the signature for a given key.
func (c Crypto) PublicPollKey(key []byte) (pubKey []byte, pubKeySig []byte, err error) {
	return []byte("publicPollKey"), []byte("publicPollKeySig"), nil
}

// Decrypt returned the plaintext from value using the key.
func (c Crypto) Decrypt(key []byte, value []byte) ([]byte, error) {
	prefix := []byte("enc:")
	return bytes.TrimPrefix(value, prefix), nil
}

// Sign returns the signature for the given data.
func (c Crypto) Sign(value []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("sig:%s", value)), nil
}
