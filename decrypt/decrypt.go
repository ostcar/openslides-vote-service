package decrypt

import (
	"context"
	"io"
)

// Decrypt holds the internal state of the decrypt component.
type Decrypt struct {
	crypto   Crypto
	auditlog Auditlog
	store    Store
}

// New returns the initialized decrypt component.
func New(crypto Crypto, auditlog Auditlog, store Store) *Decrypt {
	return &Decrypt{
		crypto:   crypto,
		auditlog: auditlog,
		store:    store,
	}
}

// Start starts the poll with specific data.
//
// It saves the poll data and generates a cryptographic key and returns the
// public key.
func (d *Decrypt) Start(ctx context.Context, id string, poll PollMeta) (pubKey []byte, err error) {
	return nil, nil
}

// Verify decryptes the given vote and returns true, if it is valid.
func (d *Decrypt) Verify(ctx context.Context, id string, vote []byte, meta VoteMeta) (valid bool, err error) {
	return false, nil
}

// Stop takes a list of ecrypted votes, decryptes them and returns them in a
// random order.
func (d *Decrypt) Stop(ctx context.Context, id string, voteList [][]byte) (decryptedVoteList []byte, err error) {
	return nil, nil
}

// Clear stops a poll by removing the generated cryptographic key. After this
// call, it is impossible to call Verify or Stop.
func (d *Decrypt) Clear(ctx context.Context, id string) (auditlog []byte, err error) {
	return nil, nil
}

// PollMeta contains all settings of a poll needed to validate the votes.
type PollMeta struct {
}

// VoteMeta contains all data specific to a vote from the OpenSlides stack, that
// is needed from the decrypt service to validate the vote.
type VoteMeta struct {
	Weight string `json:"weight"`
}

// Auditlog saves and loads the audotmessages.
type Auditlog interface {
	// Log saves a log message.
	Log(ctx context.Context, id string, event string, fmt string, a ...interface{}) error

	// Load loads all log messages for one poll.
	Load(ctx context.Context, id string) ([]string, error)
}

// Crypto implements all required cryptographic functions.
type Crypto interface {
	// CreateKey creates a new keypair and signes them using the mainKey
	CreateKey(mainKey []byte) (pollKey []byte, err error)
}

// Store saves the data, that have to be persistend.
type Store interface {
	// Save saves the data for one poll.
	Save(w io.Writer, id string) error

	// Load gets the data for one poll.
	Load(id string) (io.Reader, error)
}
