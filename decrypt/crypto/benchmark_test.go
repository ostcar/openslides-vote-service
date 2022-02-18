package crypto_test

import (
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"github.com/ostcar/eciesgo"
)

func benchmarkDecrypt(b *testing.B, voteCount int, voteByteSize int) {
	mainKey := mockPrivateSignKey(b)
	pollKey := mockPrivateEncryptKey(b)

	cr := crypto.New(mainKey.D.Bytes(), randomMock{})

	plaintext := make([]byte, voteByteSize)

	votes := make([][]byte, voteCount)
	for i := 0; i < voteCount; i++ {
		decrypted, err := eciesgo.Encrypt(randomMock{}, pollKey.PublicKey, plaintext)
		if err != nil {
			b.Fatalf("encrypting vote: %v", err)
		}
		votes[i] = decrypted
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for i := 0; i < voteCount; i++ {
			if _, err := cr.Decrypt(pollKey.Bytes(), votes[i]); err != nil {
				b.Errorf("decrypting: %v", err)
			}
		}
	}

}

func BenchmarkDecrypt1Byte100(b *testing.B)    { benchmarkDecrypt(b, 1, 100) }
func BenchmarkDecrypt10Byte100(b *testing.B)   { benchmarkDecrypt(b, 10, 100) }
func BenchmarkDecrypt100Byte100(b *testing.B)  { benchmarkDecrypt(b, 100, 100) }
func BenchmarkDecrypt1000Byte100(b *testing.B) { benchmarkDecrypt(b, 1_000, 100) }

func BenchmarkDecrypt1Byte1000(b *testing.B)    { benchmarkDecrypt(b, 1, 1_000) }
func BenchmarkDecrypt10Byte1000(b *testing.B)   { benchmarkDecrypt(b, 10, 1_000) }
func BenchmarkDecrypt100Byte1000(b *testing.B)  { benchmarkDecrypt(b, 100, 1_000) }
func BenchmarkDecrypt1000Byte1000(b *testing.B) { benchmarkDecrypt(b, 1_000, 1_000) }
