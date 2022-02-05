package decrypt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
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
// It saves the poll meta data and generates a cryptographic key and returns the
// public key.
func (d *Decrypt) Start(ctx context.Context, id string, meta PollMeta) (pubKey []byte, err error) {
	var pd pollData
	oldData, err := d.store.Load(id)
	if err != nil {
		return nil, fmt.Errorf("loading poll data: %w", err)
	}

	if oldData != nil {
		if err := json.Unmarshal(oldData, &pd); err != nil {
			return nil, fmt.Errorf("decoding poll data: %w", err)
		}

	} else {
		key, err := d.crypto.CreateKey()
		if err != nil {
			return nil, fmt.Errorf("creating poll key: %w", err)
		}

		pd.Key = key
		pd.Meta = meta

		data, err := json.Marshal(pd)
		if err != nil {
			return nil, fmt.Errorf("decoding poll data: %w", err)
		}

		if err := d.store.Save(id, data); err != nil {
			return nil, fmt.Errorf("saving data: %w", err)
		}
	}

	pubKey, err = d.crypto.SignedPubKey([]byte(pd.Key))
	if err != nil {
		return nil, fmt.Errorf("signing pub key: %w", err)
	}

	return pubKey, nil
}

// Validate decryptes the given vote and returns true, if it is valid.
func (d *Decrypt) Validate(ctx context.Context, id string, vote []byte, meta VoteMeta) (bool, error) {
	var pd pollData
	storeData, err := d.store.Load(id)
	if err != nil {
		return false, fmt.Errorf("loading poll data: %w", err)
	}

	if storeData == nil {
		return false, fmt.Errorf("unknown poll %s", id)
	}

	if err := json.Unmarshal(storeData, &pd); err != nil {
		return false, fmt.Errorf("decoding poll data: %w", err)
	}

	plaintext, err := d.crypto.Decrypt(pd.Key, vote)
	if err != nil {
		return false, fmt.Errorf("decrypting poll: %w", err)
	}

	var b ballot
	if err := json.Unmarshal(plaintext, &b); err != nil {
		return false, fmt.Errorf("decoding ballot: %w", err)
	}

	// TODO: all validation has to be in constant time.
	valid, err := validate(pd.Meta, b.Votes)
	if err != nil {
		return false, fmt.Errorf("validate vote: %w", err)
	}

	if b.PollID != id {
		return false, nil
	}

	if b.Weight != meta.Weight {
		return false, nil
	}

	if b.UserID != 0 {
		return false, nil
	}

	return valid, nil
}

// Stop takes a list of ecrypted votes, decryptes them and returns them in a
// random order.
func (d *Decrypt) Stop(ctx context.Context, id string, voteList [][]byte) (decryptedVoteList, signature []byte, err error) {
	var pd pollData
	storeData, err := d.store.Load(id)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll data: %w", err)
	}

	if storeData == nil {
		return nil, nil, fmt.Errorf("unknown poll %s", id)
	}

	if err := json.Unmarshal(storeData, &pd); err != nil {
		return nil, nil, fmt.Errorf("decoding poll data: %w", err)
	}

	decrypted := make([]json.RawMessage, len(voteList))
	for i, vote := range voteList {
		plain, err := d.crypto.Decrypt(pd.Key, vote)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypting vote: %w", err)
		}
		decrypted[i] = plain
	}

	// TODO: use crypt/rand
	rand.Shuffle(len(decrypted), func(i, j int) {
		decrypted[i], decrypted[j] = decrypted[j], decrypted[i]
	})

	content := struct {
		Meta  PollMeta          `json:"meta"`
		Votes []json.RawMessage `json:"votes"`
	}{
		pd.Meta,
		decrypted,
	}

	decryptedVoteList, err = json.Marshal(content)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding content: %w", err)
	}

	signature, err = d.crypto.Sign(decryptedVoteList)
	if err != nil {
		return nil, nil, fmt.Errorf("siging votes: %w", err)
	}

	return decryptedVoteList, signature, nil
}

// Clear stops a poll by removing the generated cryptographic key. After this
// call, it is impossible to call Verify or Stop.
func (d *Decrypt) Clear(ctx context.Context, id string) (auditlog, signatrue []byte, err error) {
	return nil, nil, errors.New("TODO")
}

// PollMeta contains all settings of a poll needed to validate the votes.
type PollMeta struct {
	Method        string `json:"method"`
	GlobalYes     bool   `json:"global_yes"`
	GlobalNo      bool   `json:"global_no"`
	GlobalAbstain bool   `json:"global_abstain"` // TEST ME
	Options       string `json:"options"`        // TODO: use better value that is comparable but returns to []int
	MaxAmount     int    `json:"max_amount"`
	MinAmount     int    `json:"min_amount"`
}

// VoteMeta contains all data specific to a vote from the OpenSlides stack, that
// is needed from the decrypt service to validate the vote.
type VoteMeta struct {
	Weight string `json:"weight"`
}

// pollData is the format stored in the storage.
type pollData struct {
	Key  []byte   `json:"key"`
	Meta PollMeta `json:"meta"`
}

type ballot struct {
	Votes  voteValue `json:"votes"`
	Weight string    `json:"weight"`
	PollID string    `json:"poll_id"`
	UserID int       `json:"user_id"`
}

// voteValue is the attribute "votes" from the user vote.
type voteValue struct {
	str          string
	optionAmount map[int]int
	optionYNA    map[int]string
}

func (v *voteValue) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &v.str); err == nil {
		// voteData is a string
		return nil
	}

	if err := json.Unmarshal(b, &v.optionAmount); err == nil {
		// voteData is option_id to amount
		return nil
	}
	v.optionAmount = nil

	if err := json.Unmarshal(b, &v.optionYNA); err == nil {
		// voteData is option_id to string
		return nil
	}

	return fmt.Errorf("unknown vote value: `%s`", b)
}

const (
	ballotValueUnknown = iota
	ballotValueString
	ballotValueOptionAmount
	ballotValueOptionString
)

func (v *voteValue) Type() int {
	if v.str != "" {
		return ballotValueString
	}

	if v.optionAmount != nil {
		return ballotValueOptionAmount
	}

	if v.optionYNA != nil {
		return ballotValueOptionString
	}

	return ballotValueUnknown
}

// Auditlog saves and loads the audotmessages.
type Auditlog interface {
	// Log saves a log message.
	Log(ctx context.Context, id string, event string, payload interface{}) error

	// Load loads all log messages for one poll.
	Load(ctx context.Context, id string) ([]string, error)
}

// Crypto implements all required cryptographic functions.
type Crypto interface {
	// CreateKey creates a new keypair. Returns the public and privat key and a
	// signature for the public key.
	CreateKey() ([]byte, error)

	// SingedPubKey returns a signed public key.
	SignedPubKey(key []byte) ([]byte, error)

	// Decrypt returned the plaintext from value using the key.
	Decrypt(key []byte, value []byte) ([]byte, error)

	// Sign data.
	Sign(value []byte) ([]byte, error)
}

// Store saves the data, that have to be persistend.
//
// The
type Store interface {
	// Save saves the data for one poll.
	Save(id string, data []byte) error

	// Load gets the data for one poll.
	Load(id string) ([]byte, error)

	// Delete removes the data for one poll.
	Delete(id string) error
}
