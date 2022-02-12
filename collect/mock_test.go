package collect_test

import (
	"context"
	"net/http"
	"testing"
)

type decrypterStub struct{}

func (d *decrypterStub) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	return nil, nil, nil
}

func (d *decrypterStub) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	return nil, nil, nil
}
func (d *decrypterStub) Clear(ctx context.Context, pollID string) error {
	return nil
}

// TODO: use objects from dsmock
type StubGetter struct {
	data      map[string][]byte
	err       error
	requested map[string]bool
}

func (g *StubGetter) Get(ctx context.Context, keys ...string) (map[string][]byte, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.requested == nil {
		g.requested = make(map[string]bool)
	}

	out := make(map[string][]byte, len(keys))
	for _, k := range keys {
		out[k] = g.data[k]
		g.requested[k] = true
	}
	return out, nil
}

func (g *StubGetter) assertKeys(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if !g.requested[key] {
			t.Errorf("Key %s is was not requested", key)
		}
	}
}

type authStub int

func (a authStub) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return r.Context(), nil
}

func (a authStub) FromContext(ctx context.Context) int {
	return int(a)
}
