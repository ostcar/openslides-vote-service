package vote

import (
	"context"
	"sync"
)

// MockCounter implements the counter interface, but inmemory.
type MockCounter struct {
	mu sync.Mutex

	counts  map[int]int // map from pollID to number of votes
	id      uint64
	changes map[uint64]int // map from id to pollID

	wait chan struct{}
}

// NewMockCounter initializes a mock counter.
func NewMockCounter() *MockCounter {
	return &MockCounter{
		counts:  make(map[int]int),
		changes: make(map[uint64]int),
		wait:    make(chan struct{}),
	}
}

// CountAdd adds one vote for the pollID to the counter.
func (c *MockCounter) CountAdd(ctx context.Context, pollID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counts[pollID]++
	c.id++
	c.changes[c.id] = pollID
	c.wakeup()

	return nil
}

// CountClear deletes all counts for a poll.
func (c *MockCounter) CountClear(ctx context.Context, pollID int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.counts, pollID)
	c.id++
	c.changes[c.id] = pollID
	c.wakeup()
	return nil
}

// ClearAll deleted all counts from all polls.
func (c *MockCounter) ClearAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counts = make(map[int]int)
	c.id = 0
	c.changes = make(map[uint64]int)
	c.wakeup()
	return nil
}

// Counters returns all counts of all polls since the given id.
//
// Returns a new ID that can be used the next time. Returns all counts for
// all polls if the id 0 is given.
//
// Blocks until there is new data.
func (c *MockCounter) Counters(ctx context.Context, id uint64, blocking bool) (newid uint64, counts map[int]int, err error) {
	c.mu.Lock()

	if id == 0 && !blocking {
		defer c.mu.Unlock()
		return c.id, nil, nil
	}

	if id < c.id {
		defer c.mu.Unlock()
		votes := make(map[int]int)
		for cid, pollID := range c.changes {
			if cid <= id {
				continue
			}
			votes[pollID] = c.counts[pollID]
		}
		return c.id, votes, err
	}

	if !blocking {
		defer c.mu.Unlock()
		return c.id, nil, nil
	}

	ch := c.wait

	c.mu.Unlock()
	select {
	case <-ch:
		// Try again. This should not be used in production. If id is a very
		// high number, this will run in a stack overflow.
		return c.Counters(ctx, id, blocking)

	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

// WaitForID waits until id x in the message bus before returing.
func (c *MockCounter) WaitForID(id uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		ch := c.wait

		c.mu.Unlock()
		<-ch
		c.mu.Lock()

		if id >= c.id {
			break
		}
	}
}

func (c *MockCounter) wakeup() {
	close(c.wait)
	c.wait = make(chan struct{})
}
