package vote_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dskey"
)

type StubGetter struct {
	data      map[dskey.Key][]byte
	err       error
	requested map[dskey.Key]bool
}

func (g *StubGetter) Get(ctx context.Context, keys ...dskey.Key) (map[dskey.Key][]byte, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.requested == nil {
		g.requested = make(map[dskey.Key]bool)
	}

	out := make(map[dskey.Key][]byte, len(keys))
	for _, k := range keys {
		out[k] = g.data[k]
		g.requested[k] = true
	}
	return out, nil
}

func (g *StubGetter) assertKeys(t *testing.T, keys ...dskey.Key) {
	t.Helper()
	for _, key := range keys {
		if !g.requested[key] {
			t.Errorf("Key %s is was not requested", key)
		}
	}
}

type autherStub struct {
	userID int
}

func (a *autherStub) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	return r.Context(), nil
}

func (a *autherStub) FromContext(context.Context) int {
	return a.userID
}
