package crypto_test

import (
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/ostcar/eciesgo"
)

func BenchmarkDecrypt(b *testing.B) {
	voteCount := 100
	mainKey := mockPrivateSignKey(b)
	pollKey := mockPrivateEncryptKey(b)

	cr := crypto.New(mainKey.D.Bytes(), readerMock{})

	votes := make([][]byte, voteCount)
	for i := 0; i < voteCount; i++ {
		decrypted, err := eciesgo.Encrypt(pollKey.PublicKey, []byte("vote"))
		if err != nil {
			b.Fatalf("encrypting vote: %v", err)
		}
		votes[i] = decrypted
	}

	b.ResetTimer()

	for i := 0; i < voteCount; i++ {
		if _, err := cr.Decrypt(pollKey.Bytes(), votes[i]); err != nil {
			b.Errorf("decrypting: %v", err)
		}
	}
}
