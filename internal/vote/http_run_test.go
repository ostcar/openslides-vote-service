package vote_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsmock"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/internal/vote"
)

func waitForServer(addr string) error {
	for i := 0; i < 100; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("waiting for server failed")
}

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := memory.New()
	ds := dsmock.Stub{}
	service := vote.New(backend, backend, ds)

	getAddr := make(chan string)
	go func() {
		lst, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Errorf("open listener: %v", err)
		}

		getAddr <- lst.Addr().String()

		if err := vote.Run(ctx, lst, new(autherStub), service); err != nil {
			t.Errorf("vote.Run: %v", err)
		}
	}()

	addr := <-getAddr

	if err := waitForServer(addr); err != nil {
		t.Errorf("waiting for server: %v", err)
	}

	t.Run("URLs", func(t *testing.T) {
		for _, url := range []string{
			"/internal/vote/start",
			"/internal/vote/stop",
			"/internal/vote/clear",
			"/internal/vote/clear_all",
			"/system/vote",
			"/system/vote/voted",
			"/internal/vote/vote_count",
			"/system/vote/health",
		} {
			resp, err := http.Get(fmt.Sprintf("http://%s%s", addr, url))
			if err != nil {
				t.Fatalf("sending request: %v", err)
			}

			if resp.StatusCode == 404 {
				t.Errorf("url %s does not exist", url)
			}
		}
	})
}
