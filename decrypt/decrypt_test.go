package decrypt_test

import (
	"context"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
)

func TestStart(t *testing.T) {
	crypto := cryptoMock{}
	store := NewStoreMock()
	d := decrypt.New(&crypto, store)

	pubKey, pubKeySig, err := d.Start(context.Background(), "test/1")
	if err != nil {
		t.Fatalf("start returned: %v", err)
	}

	if string(pubKey) != "pollPubKey" {
		t.Errorf("start returned `%s`, expected `pollPubKey`", pubKey)
	}

	if string(pubKeySig) != "pollKeySig" {
		t.Errorf("start returned `%s`, expected `pollKeySig`", pubKeySig)
	}

	// TODO: test error cases
}

func TestStop(t *testing.T) {
	crypto := cryptoMock{}
	store := NewStoreMock()
	d := decrypt.New(&crypto, store, decrypt.WithRandomSource(readerMock{}))

	if _, _, err := d.Start(context.Background(), "test/1"); err != nil {
		t.Fatalf("start: %v", err)
	}

	votes := [][]byte{
		[]byte(`enc:{"poll_id":"test/1","votes":"Y"}`),
		[]byte(`enc:{"poll_id":"test/1","votes":"N"}`),
		[]byte(`enc:{"poll_id":"test/1","votes":"A"}`),
	}

	content, signature, err := d.Stop(context.Background(), "test/1", votes)
	if err != nil {
		t.Errorf("stop: %v", err)
	}

	if string(signature) != "sig:"+string(content) {
		t.Errorf("got signature %s, expected signature %s", signature, "sig:"+string(content))
	}

	expected := `{"id":"test/1","votes":[{"poll_id":"test/1","votes":"Y"},{"poll_id":"test/1","votes":"A"},{"poll_id":"test/1","votes":"N"}]}`
	if string(content) != expected {
		t.Errorf("got %s, expected %s", content, expected)
	}

	// TODO: Test errors
	// * Wrong poll_id
	// * wrong decryption key
}

// TODO: test clear
