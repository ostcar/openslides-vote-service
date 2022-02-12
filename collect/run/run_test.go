package run_test

import (
	"bytes"
	"context"
	goLogger "log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenSlides/openslides-vote-service/collect/run"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
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
			err := run.Run(ctx, []string{"VOTE_BACKEND_FAST=memory", "VOTE_BACKEND_LONG=memory", "VOTE_PORT=5000"}, secret)
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
			runErr = run.Run(ctx, []string{"VOTE_BACKEND_FAST=memory", "VOTE_BACKEND_LONG=memory", "VOTE_PORT=5001"}, secret)
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
