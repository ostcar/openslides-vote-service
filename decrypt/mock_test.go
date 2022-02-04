package decrypt_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

type cryptoStub struct {
	mainKey []byte

	pollKey []byte
	err     error
}

func (c *cryptoStub) CreateKey(mainKey []byte) (pollKey []byte, err error) {
	c.mainKey = mainKey
	return c.pollKey, c.err
}

type AuditlogStub struct {
	id      string
	event   string
	message string

	messages []string
	err      error
}

func (al *AuditlogStub) Log(ctx context.Context, id string, event string, format string, a ...interface{}) error {
	al.id = id
	al.event = event
	al.message = fmt.Sprintf(format, a...)
	return al.err
}

func (al *AuditlogStub) Load(ctx context.Context, id string) ([]string, error) {
	al.id = id

	return al.messages, al.err
}

type StoreStub struct {
	written []byte
	id      string

	read []byte
	err  error
}

func (s *StoreStub) Save(w io.Writer, id string) error {
	w.Write(s.written)
	s.id = id
	return s.err
}

func (s *StoreStub) Load(id string) (io.Reader, error) {
	s.id = id
	return bytes.NewReader(s.read), s.err
}
