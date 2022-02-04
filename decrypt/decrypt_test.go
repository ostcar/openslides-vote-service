package decrypt_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
)

func TestStart(t *testing.T) {
	store := StoreStub{}

	d := decrypt.New(&cryptoStub{}, &AuditlogStub{}, &store)

	pub, err := d.Start(context.Background(), "test/1", decrypt.PollMeta{})
	if err != nil {
		t.Fatalf("start returned: %v", err)
	}

	if !bytes.Equal(store.written, pub) {
		// TODO: This is not correct, the function returns the public key, but
		// in the store the full key and the meta data are written.
		t.Errorf("saved `%s` in the store, expected `%s`", store.written, pub)
	}
}
