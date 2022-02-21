package decrypt_test

import (
	"bytes"
	"fmt"
)

type cryptoMock struct{}

// PublicMainKey returns the public main key and the signature of the key.
func (c cryptoMock) PublicMainKey() (pubKey []byte, err error) {
	return []byte("mainPubKey"), nil
}

// CreatePollKey creates a new keypair for a poll.
func (c cryptoMock) CreatePollKey() (key []byte, err error) {
	return []byte("pollKey"), nil
}

// PublicPollKey returns the public poll key and the signature for a given key.
func (c cryptoMock) PublicPollKey(key []byte) (pubKey []byte, pubKeySig []byte, err error) {
	return []byte("pollPubKey"), []byte("pollKeySig"), nil
}

// Decrypt returned the plaintext from value using the key.
func (c cryptoMock) Decrypt(key []byte, value []byte) ([]byte, error) {
	prefix := []byte("enc:")
	return bytes.TrimPrefix(value, prefix), nil
}

// Returns the signature for the given data.
func (c cryptoMock) Sign(value []byte) ([]byte, error) {
	return []byte(fmt.Sprintf("sig:%s", value)), nil
}

// TODO: Implement correct errors from interface
type StoreMock struct {
	keys       map[string][]byte
	signatures map[string][]byte
}

func NewStoreMock() *StoreMock {
	return &StoreMock{
		keys:       make(map[string][]byte),
		signatures: make(map[string][]byte),
	}
}

func (s *StoreMock) SaveKey(id string, key []byte) error {
	s.keys[id] = key
	return nil
}

// LoadKey returns the private key from the store.
//
// If the poll is unknown return (nil, nil)
func (s *StoreMock) LoadKey(id string) (key []byte, err error) {
	return s.keys[id], nil
}

// ValidateSignature makes sure, that no other signature is saved for a
// poll. Saves the signature for future calls.
//
// Has to return an error if the id is unknown in the store.
func (s *StoreMock) ValidateSignature(id string, signature []byte) error {
	if s.signatures[id] == nil {
		s.signatures[id] = signature
		return nil
	}
	if string(signature) != string(s.signatures[id]) {
		return fmt.Errorf("%s != %s", signature, s.signatures[id])
	}
	return nil
}

// Clear removes all data for the poll.
func (s *StoreMock) ClearPoll(id string) error {
	delete(s.keys, id)
	delete(s.signatures, id)
	return nil
}

type readerMock struct{}

func (r readerMock) Read(data []byte) (n int, err error) {
	for i := 0; i < len(data); i++ {
		data[i] = '0'
	}
	return len(data), nil
}
