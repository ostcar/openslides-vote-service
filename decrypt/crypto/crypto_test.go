package crypto_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"golang.org/x/crypto/curve25519"
)

func TestCreatePollKey(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{})

	key, err := c.CreatePollKey()
	if err != nil {
		t.Fatalf("CreatePollKey: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("created key is not valid")
	}
}

func TestPublicPollKey(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{})

	pub, sig, err := c.PublicPollKey(mockPollKey())
	if err != nil {
		t.Fatalf("PublicPollKey: %v", err)
	}

	if !ed25519.Verify(ed25519.NewKeyFromSeed(mockMainKey()).Public().(ed25519.PublicKey), pub, sig) {
		t.Errorf("signature does not match public key")
	}
}

func TestDecrypt(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{})

	plaintext := "this is my vote"

	privKey := make([]byte, 32)
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("creating public key: %v", err)
	}

	encrypted, err := crypto.Encrypt(randomMock{}, pubKey, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypting plaintext: %v", err)
	}

	decrypted, err := c.Decrypt(privKey, encrypted)
	if err != nil {
		t.Errorf("decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("decrypt got `%s`, expected `%s`", decrypted, plaintext)
	}
}

func TestSign(t *testing.T) {
	c := crypto.New(mockMainKey(), randomMock{})

	data := []byte("this is my value")

	sig, err := c.Sign(data)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if !ed25519.Verify(ed25519.NewKeyFromSeed(mockMainKey()).Public().(ed25519.PublicKey), data, sig) {
		t.Errorf("signature does not match public key")
	}
}

func mockPollKey() []byte {
	return make([]byte, curve25519.PointSize)
}

func mockMainKey() []byte {
	return make([]byte, 32)
}

type randomMock struct{}

func (r randomMock) Read(data []byte) (n int, err error) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
	return len(data), nil
}
