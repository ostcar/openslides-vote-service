// Package memory implements the vote.Backend interface.
//
// All data are saved in memory. The main use is testing.
package memory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
)

// Backend is a simple vote backend that can be used for
// testing.
type Backend struct {
	mu      sync.Mutex
	voted   map[int]map[int]bool
	objects map[int][][]byte
	state   map[int]int

	pollKey       map[string][]byte
	pollSignature map[string][]byte
}

// New initializes a new memory.Backend.
func New() *Backend {
	b := Backend{
		voted:         make(map[int]map[int]bool),
		objects:       make(map[int][][]byte),
		state:         make(map[int]int),
		pollKey:       make(map[string][]byte),
		pollSignature: make(map[string][]byte),
	}
	return &b
}

func (b *Backend) String() string {
	return "memory"
}

// Start opens opens a poll.
func (b *Backend) Start(ctx context.Context, pollID int) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state[pollID] == 2 {
		return nil
	}
	b.state[pollID] = 1
	return nil
}

// Vote saves a vote.
func (b *Backend) Vote(ctx context.Context, pollID int, userID int, object []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state[pollID] == 0 {
		return 0, doesNotExistError{fmt.Errorf("poll is not open")}
	}

	if b.state[pollID] == 2 {
		return 0, stoppedError{fmt.Errorf("Poll is stopped")}
	}

	if b.voted[pollID] == nil {
		b.voted[pollID] = make(map[int]bool)
	}

	if _, ok := b.voted[pollID][userID]; ok {
		return 0, doupleVoteError{fmt.Errorf("user has already voted")}
	}

	b.voted[pollID][userID] = true
	b.objects[pollID] = append(b.objects[pollID], object)
	return len(b.voted[pollID]), nil
}

// Stop stopps a poll.
func (b *Backend) Stop(ctx context.Context, pollID int) ([][]byte, []int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state[pollID] == 0 {
		return nil, nil, doesNotExistError{fmt.Errorf("Poll does not exist")}
	}

	b.state[pollID] = 2

	userIDs := make([]int, 0, len(b.voted[pollID]))
	for id := range b.voted[pollID] {
		userIDs = append(userIDs, id)
	}
	sort.Ints(userIDs)
	return b.objects[pollID], userIDs, nil
}

// Clear removes all data for a poll.
func (b *Backend) Clear(ctx context.Context, pollID int) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.voted, pollID)
	delete(b.objects, pollID)
	delete(b.state, pollID)
	return nil
}

// ClearAll removes all data for all polls.
func (b *Backend) ClearAll(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.voted = make(map[int]map[int]bool)
	b.objects = make(map[int][][]byte)
	b.state = make(map[int]int)
	return nil
}

// VotedPolls tells for a list of poll IDs if the given userID has already
// voted.
func (b *Backend) VotedPolls(ctx context.Context, pollIDs []int, userID int) (map[int]bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make(map[int]bool)
	for _, id := range pollIDs {
		out[id] = b.voted[id][userID]
	}
	return out, nil
}

// AssertUserHasVoted is a method for the tests to check, if a user has voted.
func (b *Backend) AssertUserHasVoted(t *testing.T, pollID, userID int) {
	t.Helper()

	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.voted[pollID][userID] {
		t.Errorf("User %d has not voted", userID)
	}
}

// SaveKey saves a poll key.
func (b *Backend) SaveKey(id string, key []byte) error {
	b.pollKey[id] = key
	return nil
}

// LoadKey returns the private key from the store.
//
// If the poll is unknown return (nil, nil)
func (b *Backend) LoadKey(id string) (key []byte, err error) {
	return b.pollKey[id], nil
}

// ValidateSignature makes sure, that no other signature is saved for a
// poll. Saves the signature for future calls.
//
// Has to return an error if the id is unknown in the store.
func (b *Backend) ValidateSignature(id string, hash []byte) error {
	if b.pollSignature[id] == nil {
		b.pollSignature[id] = hash
		return nil
	}
	if string(hash) != string(b.pollSignature[id]) {
		return fmt.Errorf("%s != %s", hash, b.pollSignature[id])
	}
	return nil
}

// ClearPoll removes all data for the poll.
func (b *Backend) ClearPoll(id string) error {
	delete(b.pollKey, id)
	delete(b.pollSignature, id)
	return nil
}

type doesNotExistError struct {
	error
}

func (doesNotExistError) DoesNotExist() {}

type doupleVoteError struct {
	error
}

func (doupleVoteError) DoupleVote() {}

type stoppedError struct {
	error
}

func (stoppedError) Stopped() {}
