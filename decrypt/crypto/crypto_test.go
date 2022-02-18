package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/ostcar/eciesgo"
	"golang.org/x/crypto/curve25519"
)

func TestCreatePollKey(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), randomMock{})

	key, err := c.CreatePollKey()
	if err != nil {
		t.Fatalf("CreatePollKey: %v", err)
	}

	if key == nil || !bytes.Equal(key, mockPrivateEncryptKey(t).Bytes()) {
		t.Errorf("poll key != mock private Key. Expected them to be the same in testing")
	}
}

func TestPublicPollKey(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), randomMock{})

	pub, sig, err := c.PublicPollKey(mockPrivateEncryptKey(t).Bytes())
	if err != nil {
		t.Fatalf("PublicPollKey: %v", err)
	}

	mockPublic := eciesgo.NewPrivateKeyFromBytes(mockPrivateEncryptKey(t).Bytes()).PublicKey.Bytes(true)

	if pub == nil || !bytes.Equal(pub, mockPublic) {
		t.Errorf("pub key != pub mock key. Expected them to be the same in testing")
	}

	if !ecdsa.VerifyASN1(&mockPrivateSignKey(t).PublicKey, pub, sig) {
		t.Errorf("signature does not match public key")
	}
}

func TestDecrypt(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), randomMock{})

	plaintext := "this is my vote"

	privKey := make([]byte, 32)
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("creating public key: %v", err)
	}

	encrypted, err := c.Encrypt(randomMock{}, pubKey, []byte(plaintext))
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
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), randomMock{})

	data := []byte("this is my value")
	hash := sha512.New().Sum(data)

	sig, err := c.Sign(data)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if !ecdsa.VerifyASN1(&mockPrivateSignKey(t).PublicKey, hash, sig) {
		t.Errorf("sig does not match")
	}

}

func mockPrivateEncryptKey(t testing.TB) *eciesgo.PrivateKey {
	t.Helper()

	key, err := eciesgo.GenerateKey(randomMock{})
	if err != nil {
		t.Fatalf("creating key: %v", err)
	}

	return key
}

func mockPrivateSignKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P521(), randomMock{})
	if err != nil {
		t.Fatalf("creating key: %v", err)
	}

	return k
}

type randomMock struct{}

func (r randomMock) Read(data []byte) (n int, err error) {
	for i := 0; i < len(data); i++ {
		data[i] = '0'
	}
	return len(data), nil
}
