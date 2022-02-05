package decrypt_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

type cryptoStub struct {
	createKey    string
	createErr    error
	calledCreate bool

	pubGotKey string
	pubKey    string
	pubErr    error
}

func (c *cryptoStub) CreateKey() ([]byte, error) {
	c.calledCreate = true
	return []byte(c.createKey), c.createErr
}

func (c *cryptoStub) SignedPubKey(key []byte) ([]byte, error) {
	c.pubGotKey = string(key)
	return []byte(c.pubKey), c.pubErr
}

func (c *cryptoStub) Decrypt(key []byte, value []byte) ([]byte, error) {
	v := bytes.TrimPrefix(value, []byte("enc:"))
	if string(v) == string(value) {
		return nil, fmt.Errorf("value not encrypted")
	}
	return v, nil
}

func (c *cryptoStub) Sign(value []byte) ([]byte, error) {
	return append([]byte("sig:"), value...), nil
}

type AuditlogStub struct {
	messages []string
	logErr   error

	loadID       string
	loadMessages []string
	loadErr      error
}

func (al *AuditlogStub) Log(ctx context.Context, id string, event string, payload interface{}) error {
	p, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	msg := fmt.Sprintf("%s:%s:%s", id, event, p)
	al.messages = append(al.messages, msg)
	return al.logErr
}

func (al *AuditlogStub) Load(ctx context.Context, id string) ([]string, error) {
	al.loadID = id
	return al.loadMessages, al.loadErr
}

type StoreStub struct {
	saveData string
	saveID   string
	saveErr  error

	loadID   string
	loadData string
	loadErr  error

	deleteID  string
	deleteErr error
}

func (s *StoreStub) Save(id string, data []byte) error {
	s.saveData = string(data)
	s.saveID = id
	return s.saveErr
}

func (s *StoreStub) Load(id string) ([]byte, error) {
	s.loadID = id
	if s.loadData == "" {
		return nil, s.loadErr
	}
	return []byte(s.loadData), s.loadErr
}

func (s *StoreStub) Delete(id string) error {
	s.deleteID = id
	return s.deleteErr
}
