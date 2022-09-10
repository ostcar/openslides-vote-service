package vote_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore"
)

type StubGetter struct {
	data      map[datastore.Key][]byte
	err       error
	requested map[datastore.Key]bool
}

func (g *StubGetter) Get(ctx context.Context, keys ...datastore.Key) (map[datastore.Key][]byte, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.requested == nil {
		g.requested = make(map[datastore.Key]bool)
	}

	out := make(map[datastore.Key][]byte, len(keys))
	for _, k := range keys {
		out[k] = g.data[k]
		g.requested[k] = true
	}
	return out, nil
}

func (g *StubGetter) assertKeys(t *testing.T, keys ...datastore.Key) {
	t.Helper()
	for _, key := range keys {
		if !g.requested[key] {
			t.Errorf("Key %s is was not requested", key)
		}
	}
}

func MustKey(in string) datastore.Key {
	k, err := datastore.KeyFromString(in)
	if err != nil {
		panic(err)
	}
	return k
}

type decrypterStub struct{}

func (d *decrypterStub) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	return nil, nil, nil
}

func (d *decrypterStub) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	votes := make([]json.RawMessage, len(voteList))
	for i, vote := range voteList {
		votes[i] = vote
	}

	decryptedContent, err = json.Marshal(votes)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal decrypted content: %w", err)
	}

	return decryptedContent, []byte("signature"), nil
}

func (d *decrypterStub) Clear(ctx context.Context, pollID string) error {
	return nil
}
