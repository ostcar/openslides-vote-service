package crypto_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/ostcar/eciesgo"
)

func TestCreatePollKey(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), readerMock{})

	key, err := c.CreatePollKey()
	if err != nil {
		t.Fatalf("CreatePollKey: %v", err)
	}

	if key == nil || !bytes.Equal(key, mockPrivateEncryptKey(t).Bytes()) {
		t.Errorf("poll key != mock private Key. Expected them to be the same in testing")
	}
}

func TestPublicPollKey(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), readerMock{})

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
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), readerMock{})

	plaintext := "this is my vote"

	encrypted, err := eciesgo.Encrypt(mockPrivateEncryptKey(t).PublicKey, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypting plaintext: %v", err)
	}

	decrypted, err := c.Decrypt(mockPrivateEncryptKey(t).Bytes(), encrypted)
	if err != nil {
		t.Errorf("decrypt: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("decrypt got `%s`, expected `%s`", decrypted, plaintext)
	}
}

func TestSign(t *testing.T) {
	c := crypto.New(mockPrivateSignKey(t).D.Bytes(), readerMock{})

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

	key, err := eciesgo.GenerateKey(readerMock{})
	if err != nil {
		t.Fatalf("creating key: %v", err)
	}

	return key
}

func mockPrivateSignKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P521(), readerMock{})
	if err != nil {
		t.Fatalf("creating key: %v", err)
	}

	return k
}

type readerMock struct{}

func (r readerMock) Read(data []byte) (n int, err error) {
	for i := 0; i < len(data); i++ {
		data[i] = '0'
	}
	return len(data), nil
}
