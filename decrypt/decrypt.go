package decrypt

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"runtime"
	"sync"
)

// Decrypt holds the internal state of the decrypt component.
type Decrypt struct {
	crypto Crypto
	store  Store

	maxVotes       int
	decryptWorkers int
	random         io.Reader
}

// New returns the initialized decrypt component.
func New(crypto Crypto, store Store, options ...Option) *Decrypt {
	d := Decrypt{
		crypto:         crypto,
		store:          store,
		decryptWorkers: runtime.GOMAXPROCS(-1),
		random:         rand.Reader,
		maxVotes:       math.MaxInt,
	}

	for _, o := range options {
		o(&d)
	}

	return &d
}

// Start starts the poll with specific data.
//
// It saves the poll meta data and generates a cryptographic key and returns the
// public key.
func (d *Decrypt) Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error) {
	pollKey, err := d.store.LoadKey(pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll key: %w", err)
	}

	if pollKey == nil {
		key, err := d.crypto.CreatePollKey()
		if err != nil {
			return nil, nil, fmt.Errorf("creating poll key: %w", err)
		}
		pollKey = key

		if err := d.store.SaveKey(pollID, key); err != nil {
			return nil, nil, fmt.Errorf("saving poll key: %w", err)
		}
	}

	pubKey, pubKeySig, err = d.crypto.PublicPollKey(pollKey)
	if err != nil {
		return nil, nil, fmt.Errorf("signing pub key: %w", err)
	}

	return pubKey, pubKeySig, nil
}

// Stop takes a list of ecrypted votes, decryptes them and returns them in a
// random order together with a signature.
func (d *Decrypt) Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error) {
	pollKey, err := d.store.LoadKey(pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll key: %w", err)
	}

	if pollKey == nil {
		return nil, nil, fmt.Errorf("unknown poll")
	}

	if len(voteList) > d.maxVotes {
		return nil, nil, fmt.Errorf("received %d votes, only %d votes supported", len(voteList), d.maxVotes)
	}

	decrypted, err := d.decryptVotes(ctx, pollKey, voteList)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypting votes: %w", err)
	}

	content := struct {
		ID    string            `json:"id"`
		Votes []json.RawMessage `json:"votes"`
	}{
		pollID,
		decrypted,
	}

	decryptedContent, err = json.Marshal(content)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal decrypted content: %w", err)
	}

	signature, err = d.crypto.Sign(decryptedContent)
	if err != nil {
		return nil, nil, fmt.Errorf("signing votes")
	}

	if err := d.store.ValidateSignature(pollID, signature); err != nil {
		return nil, nil, fmt.Errorf("validate signature: %w", err)
	}

	return decryptedContent, signature, nil
}

// Clear stops a poll by removing the generated cryptographic key.
func (d *Decrypt) Clear(ctx context.Context, pollID string) error {
	if err := d.store.ClearPoll(pollID); err != nil {
		return fmt.Errorf("clearing poll from store: %w", err)
	}
	return nil
}

func randInt(source io.Reader, n int) (int, error) {
	if n == 0 {
		return 0, nil
	}

	r, err := rand.Int(source, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("getting random number from rand.Int: %w", err)
	}

	return int(r.Int64()), nil
}

func (d *Decrypt) decryptVotes(ctx context.Context, key []byte, voteList [][]byte) ([]json.RawMessage, error) {
	// TODO: Listen on ctx.Done()

	// Read votes from voteList in random order.
	voteChan := make(chan []byte, 1)
	go func() {
		defer close(voteChan)

		n := len(voteList)
		for n > 0 {
			i, err := randInt(d.random, n-1)
			if err != nil {
				// TODO: handle error
				panic(err)
			}

			voteChan <- voteList[i]
			voteList[i] = voteList[n-1]
			n--
		}
	}()

	// decrypt votes in parallel
	var wg sync.WaitGroup
	wg.Add(d.decryptWorkers)
	decryptedChan := make(chan []byte, 1)
	for i := 0; i < d.decryptWorkers; i++ {
		go func() {
			defer wg.Done()
			for vote := range voteChan {
				decrypted, err := d.crypto.Decrypt(key, vote)
				if err != nil {
					// TODO: Handle error
					decrypted = []byte(fmt.Sprintf("error decrypting: %v", err))
				}

				// TODO:Check poll ID
				decryptedChan <- decrypted
			}
		}()
	}

	go func() {
		wg.Wait()
		close(decryptedChan)
	}()

	// Bundle decrypted votes.
	decryptedList := make([]json.RawMessage, len(voteList))
	var i int
	for decrypted := range decryptedChan {
		decryptedList[i] = decrypted
		i++
	}
	return decryptedList, nil
}

// Crypto implements all required cryptographic functions.
type Crypto interface {
	// CreatePollKey creates a new keypair for a poll.
	CreatePollKey() (key []byte, err error)

	// PublicPollKey returns the public poll key and the signature for a given key.
	PublicPollKey(key []byte) (pubKey []byte, pubKeySig []byte, err error)

	// Decrypt returned the plaintext from value using the key.
	Decrypt(key []byte, value []byte) ([]byte, error)

	// Returns the signature for the given data.
	Sign(value []byte) ([]byte, error)
}

// Store saves the data, that have to be persistend.
type Store interface {
	// SaveKey stores the private key.
	//
	// Has to return an error, if a key already exists.
	SaveKey(id string, key []byte) error

	// LoadKey returns the private key from the store.
	//
	// If the poll is unknown return (nil, nil)
	LoadKey(id string) (key []byte, err error)

	// ValidateSignature makes sure, that no other signature is saved for a
	// poll. Saves the signature for future calls.
	//
	// Has to return an error if the id is unknown in the store.
	ValidateSignature(id string, hash []byte) error

	// ClearPoll removes all data for the poll.
	ClearPoll(id string) error
}
