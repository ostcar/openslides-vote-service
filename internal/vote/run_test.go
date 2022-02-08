package vote_test

import (
	"bytes"
	"context"
	goLogger "log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
	"github.com/OpenSlides/openslides-vote-service/internal/vote"
)

func waitForServer(t *testing.T, addr string) {
	for i := 0; i < 100; i++ {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("waiting for server failed")
}

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logmock := testLog{}
	log.SetInfoLogger(goLogger.New(&logmock, "", 0))
	defer log.SetInfoLogger(nil)

	t.Run("Start Server with given port", func(t *testing.T) {
		go func() {
			err := vote.Run(ctx, []string{"VOTE_BACKEND_FAST=memory", "VOTE_BACKEND_LONG=memory", "VOTE_PORT=5000"}, secret)
			if err != nil {
				t.Errorf("Vote.Run retunred unexpected error: %v", err)
			}
		}()

		waitForServer(t, "localhost:5000")

		if got := logmock.LastMSG(); got != "Listen on :5000" {
			t.Errorf("Expected listen on message, got: %s", got)
		}
	})

	t.Run("Cancel Server", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		var runErr error
		done := make(chan struct{})
		go func() {
			// Use an individuel port because the default port could be used by other tests.
			runErr = vote.Run(ctx, []string{"VOTE_BACKEND_FAST=memory", "VOTE_BACKEND_LONG=memory", "VOTE_PORT=5001"}, secret)
			close(done)
		}()

		waitForServer(t, "localhost:5001")

		// Stop the context.
		cancel()

		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			t.Errorf("Server did not stop")
		}

		if runErr != nil {
			t.Errorf("Vote.Run retunred unexpected error: %v", runErr)
		}
	})

	t.Run("Registered handlers", func(t *testing.T) {
		var runErr error
		go func() {
			// Use an individuel port because the default port could be used by other tests.
			runErr = vote.Run(ctx, []string{"VOTE_BACKEND_FAST=memory", "VOTE_BACKEND_LONG=memory", "VOTE_PORT=5002"}, secret)
		}()

		waitForServer(t, "localhost:5002")

		baseUrl := "http://localhost:5002"

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
				resp, err := http.Get(baseUrl + path)
				if err != nil {
					t.Fatalf("Can not open connection: %v", err)
				}

				if resp.StatusCode == 404 {
					t.Errorf("Got status %s", resp.Status)
				}
			})
		}

		if runErr != nil {
			t.Errorf("Vote.Run retunred unexpected error: %v", runErr)
		}
	})
}

type testLog struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	lastMSG string
}

func (l *testLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.lastMSG = strings.TrimSpace(string(p))
	return l.buf.Write(p)
}

func (l *testLog) LastMSG() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.lastMSG
}

func secret(name string) (string, error) {
	return "secret", nil
}
