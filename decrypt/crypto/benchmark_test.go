package crypto_test

import (
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt/crypto"
	"golang.org/x/crypto/curve25519"
)

func benchmarkDecrypt(b *testing.B, voteCount int, voteByteSize int) {
	cr := crypto.New(mockPrivateSignKey(b).D.Bytes(), randomMock{})

	plaintext := make([]byte, voteByteSize)

	privKey := make([]byte, 32)
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		b.Fatalf("creating public key: %v", err)
	}

	votes := make([][]byte, voteCount)
	for i := 0; i < voteCount; i++ {
		encrypted, err := cr.Encrypt(randomMock{}, pubKey, plaintext)
		if err != nil {
			b.Fatalf("encrypting vote: %v", err)
		}
		votes[i] = encrypted
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		for i := 0; i < voteCount; i++ {
			if _, err := cr.Decrypt(privKey, votes[i]); err != nil {
				b.Errorf("decrypting: %v", err)
			}
		}
	}

}

func BenchmarkDecrypt1Byte100(b *testing.B)    { benchmarkDecrypt(b, 1, 100) }
func BenchmarkDecrypt10Byte100(b *testing.B)   { benchmarkDecrypt(b, 10, 100) }
func BenchmarkDecrypt100Byte100(b *testing.B)  { benchmarkDecrypt(b, 100, 100) }
func BenchmarkDecrypt1000Byte100(b *testing.B) { benchmarkDecrypt(b, 1_000, 100) }

// func BenchmarkDecrypt10000Byte100(b *testing.B)  { benchmarkDecrypt(b, 10_000, 100) }
// func BenchmarkDecrypt100000Byte100(b *testing.B) { benchmarkDecrypt(b, 100_000, 100) }

func BenchmarkDecrypt1Byte1000(b *testing.B)    { benchmarkDecrypt(b, 1, 1_000) }
func BenchmarkDecrypt10Byte1000(b *testing.B)   { benchmarkDecrypt(b, 10, 1_000) }
func BenchmarkDecrypt100Byte1000(b *testing.B)  { benchmarkDecrypt(b, 100, 1_000) }
func BenchmarkDecrypt1000Byte1000(b *testing.B) { benchmarkDecrypt(b, 1_000, 1_000) }
