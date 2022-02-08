package vote_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
)

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

type StubMessageBus struct {
	mu       sync.Mutex
	messages [][2]string
	ch       chan [2]string
}

func NewStubMessageBus() *StubMessageBus {
	return &StubMessageBus{
		ch: make(chan [2]string, 100),
	}
}

func (m *StubMessageBus) Publish(ctx context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	msg := [2]string{key, string(value)}

	m.messages = append(m.messages, msg)
	m.ch <- msg
	return nil
}

func (m *StubMessageBus) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return len(m.messages)
}

// Read reads the next message from the bus. Blogs until the message is ready.
//
// Only one subscriber is supported.
func (m *StubMessageBus) Read(timeout time.Duration) ([2]string, error) {
	if timeout == 0 {
		return <-m.ch, nil
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case msg := <-m.ch:
		return msg, nil
	case <-timer.C:
		return [2]string{}, errors.New("timeout")
	}
}

type decrypterStub struct{}

func (d *decrypterStub) Start(ctx context.Context, id string, meta decrypt.PollMeta) (pubKey []byte, err error) {
	return nil, nil
}
func (d *decrypterStub) Validate(ctx context.Context, id string, vote []byte, meta decrypt.VoteMeta) (bool, error) {
	return false, nil
}
func (d *decrypterStub) Stop(ctx context.Context, id string, voteList [][]byte) (decryptedVoteList, signature []byte, err error) {
	return nil, nil, nil
}
func (d *decrypterStub) Clear(ctx context.Context, id string) (auditlog, signatrue []byte, err error) {
	return nil, nil, nil
}
