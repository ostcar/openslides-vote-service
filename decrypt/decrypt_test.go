package decrypt_test

import (
	"context"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
)

func TestStart(t *testing.T) {
	crypto := cryptoStub{
		createKey: "full-key",
		pubKey:    "singed-public-key",
	}

	t.Run("first time", func(t *testing.T) {
		store := StoreStub{}
		d := decrypt.New(&crypto, &AuditlogStub{}, &store)

		key, err := d.Start(context.Background(), "test/1", decrypt.PollMeta{})
		if err != nil {
			t.Fatalf("start returned: %v", err)
		}

		if string(key) != "singed-public-key" {
			t.Errorf("start returned `%s`, expected `singed-public-key`", key)
		}

		expect := `{"key":"ZnVsbC1rZXk=","meta":{"method":"","global_yes":false,"global_no":false,"global_abstain":false,"options":"","max_amount":0,"min_amount":0}}`
		if store.saveData != expect {
			t.Errorf("start wrote `%s`, expected `%s`", store.saveData, expect)
		}
	})

	t.Run("with data", func(t *testing.T) {
		crypto.calledCreate = false
		store := StoreStub{
			loadData: `{"key":"ZnVsbC1rZXk=","meta":{}}`,
		}
		d := decrypt.New(&crypto, &AuditlogStub{}, &store)

		key, err := d.Start(context.Background(), "test/1", decrypt.PollMeta{})
		if err != nil {
			t.Fatalf("start returned: %v", err)
		}

		if crypto.calledCreate {
			t.Errorf("second start created a new key")
		}

		if string(key) != "singed-public-key" {
			t.Errorf("start returned `%s`, expected `singed-public-key`", key)
		}

		if store.saveData != "" {
			t.Errorf("start wrote `%s`, expected no call", store.saveData)
		}
	})
}
