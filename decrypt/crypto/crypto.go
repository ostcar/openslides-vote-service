package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"io"
	"math/big"

	"github.com/ostcar/eciesgo"
	"golang.org/x/crypto/curve25519"
)

const (
	pubKeySize = 32
	ivSize     = aes.BlockSize
)

// Crypto implements all cryptographic functions needed for the decrypt service.
type Crypto struct {
	mainKey ecdsa.PrivateKey
	random  io.Reader
}

// New initializes a Crypto object with a main key and a random source.
//
// mainKey ....
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
func (c Crypto) Decrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	ephemeralPublicKey := ciphertext[:pubKeySize]
	iv := ciphertext[pubKeySize : pubKeySize+ivSize]

	sharedKey, err := curve25519.X25519(privateKey, ephemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating shared secred: %w", err)
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("creating aes chipher: %w", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext)-pubKeySize-ivSize)
	mode.CryptBlocks(plaintext, ciphertext[pubKeySize+ivSize:])

	return plaintext, nil
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

// Encrypt creates a cyphertext from plaintext using the given public key.
func (c Crypto) Encrypt(random io.Reader, publicKey []byte, plaintext []byte) ([]byte, error) {
	ciphertext := make([]byte, pubKeySize+ivSize+len(plaintext))

	ephemeralPrivateKey := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(random, ephemeralPrivateKey); err != nil {
		return nil, fmt.Errorf("reading from random source: %w", err)
	}

	ephemeralPublicKey, err := curve25519.X25519(ephemeralPrivateKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("creating ephemeral public key: %w", err)
	}
	copy(ciphertext[:pubKeySize], ephemeralPublicKey)

	sharedKey, err := curve25519.X25519(ephemeralPrivateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("creating shared secred: %w", err)
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("creating aes chipher: %w", err)
	}

	iv := ciphertext[pubKeySize : pubKeySize+ivSize]
	if _, err := random.Read(iv); err != nil {
		return nil, fmt.Errorf("read random for nonce: %w", err)
	}

	// TODO: add padding https://tools.ietf.org/html/rfc5246#section-6.2.3.2

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[pubKeySize+ivSize:], plaintext)

	// TODO hmac

	return ciphertext, nil
}
