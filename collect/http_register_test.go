package collect_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/dsmock"
	"github.com/OpenSlides/openslides-vote-service/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/collect"
)

func TestRegisteredHandlers(t *testing.T) {
	auth := authStub(1)
	backend := memory.New()
	ds := dsmock.Stub(nil)
	counter := collect.NewMockCounter()
	decrypter := &decrypterStub{}
	service, err := collect.New(backend, backend, ds, counter, decrypter)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	mux := http.NewServeMux()
	collect.RegisterHandler(mux, service, auth)

	for _, path := range []string{
		"/internal/vote/start",
		"/internal/vote/stop",
		"/internal/vote/clear",
		"/internal/vote/clear_all",
		"/internal/vote/vote_count",
		"/system/vote",
		"/system/vote/voted",
		"/system/vote/health",
	} {
		t.Run(path, func(t *testing.T) {
			resp := httptest.NewRecorder()
			req := httptest.NewRequest("GET", path, nil)
			mux.ServeHTTP(resp, req)

			if got := resp.Result().StatusCode; got == 404 {
				t.Errorf("Got status %d", got)
			}
		})
	}
}
