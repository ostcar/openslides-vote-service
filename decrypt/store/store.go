package store

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
)

// Store implements the decrypt.Store interface by writing the data to files.
//
// If only one instance of the decrypt service is running, this is concurrency
// save. If more then one process is running, it depends on the features of the
// filesystem.
//
// For each poll, two files are created. `POLLID_key` that contains the private
// key for the poll and `POLLID_hash` the contains the hash of the first stop
// request.
type Store struct {
	mu sync.Mutex

	path string
}

// New initializes a new Store.
func New(path string) *Store {
	return &Store{
		path: path,
	}
}

func (s *Store) keyFile(id string) string {
	// TODO: id has to be a valid file path
	id = strings.ReplaceAll(id, "/", "_")
	return path.Join(s.path, id+"_key")
}

func (s *Store) hashFile(id string) string {
	// TODO: id has to be a valid file path
	id = strings.ReplaceAll(id, "/", "_")
	return path.Join(s.path, id+"_hash")
}

// SaveKey stores the private key.
//
// Has to return an error, if a key already exists.
func (s *Store) SaveKey(id string, key []byte) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.path, os.ModePerm); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	f, err := os.OpenFile(s.keyFile(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		// TODO: better error handeling if file already existed.
		return fmt.Errorf("create file: %w", err)
	}

	defer func() {
		if cErr := f.Close(); err == nil && cErr != nil {
			err = fmt.Errorf("closing file: %w", err)
		}
	}()

	if _, err := f.Write(key); err != nil {
		return fmt.Errorf("writing key: %w", err)
	}

	return nil
}

// LoadKey returns the private key from the store.
//
// If the poll is unknown return (nil, nil)
func (s *Store) LoadKey(id string) (key []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, err = os.ReadFile(s.keyFile(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	return key, nil
}

// ValidateSignature makes sure, that no other signature is saved for a
// poll. Saves the signature for future calls.
//
// Has to return an error if the id is unknown in the store.
func (s *Store) ValidateSignature(id string, hash []byte) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(s.keyFile(id)); err != nil {
		return fmt.Errorf("checking key file: %w", err)
	}

	f, err := os.OpenFile(s.hashFile(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		// TODO: if file already exists, check the hash.
		return fmt.Errorf("create file: %w", err)
	}

	defer func() {
		if cErr := f.Close(); err == nil && cErr != nil {
			err = fmt.Errorf("closing file: %w", err)
		}
	}()

	if _, err := f.Write(hash); err != nil {
		return fmt.Errorf("writing hash: %w", err)
	}

	return nil
}

// ClearPoll removes all data for the poll.
func (s *Store) ClearPoll(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TODO: ignore, when files do not exist.

	if err := os.Remove(s.keyFile(id)); err != nil {
		return fmt.Errorf("deleting key file: %w", err)
	}

	if err := os.Remove(s.hashFile(id)); err != nil {
		return fmt.Errorf("deleting hash file: %w", err)
	}

	return nil
}
