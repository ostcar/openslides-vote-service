package decrypt_test

import (
	"context"
	"encoding/json"
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

func TestStop(t *testing.T) {
	crypto := cryptoStub{
		createKey: "full-key",
		pubKey:    "singed-public-key",
	}

	store := StoreStub{
		loadData: `{"key":"ZnVsbC1rZXk=","meta":{}}`,
	}
	d := decrypt.New(&crypto, &AuditlogStub{}, &store)

	pollMeta := decrypt.PollMeta{}

	if _, err := d.Start(context.Background(), "test/1", pollMeta); err != nil {
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
		t.Errorf("got signature %s, expected signature", signature)
	}

	var decoded struct {
		Meta  decrypt.PollMeta  `json:"meta"`
		Votes []json.RawMessage `json:"votes"`
	}
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Errorf("decoding votes: %v", err)
	}

	if pollMeta != decoded.Meta {
		t.Errorf("start returned meta %v, expected %v", decoded.Meta, pollMeta)
	}

	if len(decoded.Votes) != 3 {
		t.Errorf("returned %d votes, expected 3", len(decoded.Votes))
	}

	for _, gotVote := range decoded.Votes {
		var found bool
		for _, expectedVote := range votes {
			if "enc:"+string(gotVote) == string(expectedVote) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vote %s was not expected", gotVote)
		}
	}
}
