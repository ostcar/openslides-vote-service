package decrypt_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/decrypt"
)

func TestValidate(t *testing.T) {
	crypto := cryptoStub{
		createKey: "full-key",
		pubKey:    "singed-public-key",
	}
	store := StoreStub{}
	auditlog := AuditlogStub{}
	d := decrypt.New(&crypto, &auditlog, &store)

	for _, tt := range []struct {
		name        string
		meta        decrypt.PollMeta
		vote        string
		expectValid bool
	}{
		// Test Method Y and N.
		{
			"Method Y, Global Y, Vote Y",
			decrypt.PollMeta{
				Method:    "Y",
				GlobalYes: true,
			},
			`"Y"`,
			true,
		},
		{
			"Method Y, Vote Y",
			decrypt.PollMeta{
				Method:    "Y",
				GlobalYes: false,
			},
			`"Y"`,
			false,
		},
		{
			"Method Y, Vote N",
			decrypt.PollMeta{
				Method:   "Y",
				GlobalNo: false,
			},
			`"N"`,
			false,
		},
		{
			// The poll config is invalid. A poll with method Y should not allow global_no.
			"Method Y, Global N, Vote N",
			decrypt.PollMeta{
				Method:   "Y",
				GlobalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method N, Global N, Vote N",
			decrypt.PollMeta{
				Method:   "N",
				GlobalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method Y, Vote Option",
			decrypt.PollMeta{
				Method:  "Y",
				Options: "1,2",
			},
			`{"1":1}`,
			true,
		},
		{
			"Method Y, Vote on to many Options",
			decrypt.PollMeta{
				Method:  "Y",
				Options: "1,2",
			},
			`{"1":1,"2":1}`,
			false,
		},
		{
			"Method Y, Vote on one option with to high amount",
			decrypt.PollMeta{
				Method:  "Y",
				Options: "1,2",
			},
			`{"1":5}`,
			false,
		},
		{
			"Method Y, Vote on many option with to high amount",
			decrypt.PollMeta{
				Method:    "Y",
				Options:   "1,2",
				MaxAmount: 2,
			},
			`{"1":1,"2":2}`,
			false,
		},
		{
			"Method Y, Vote on one option with correct amount",
			decrypt.PollMeta{
				Method:    "Y",
				Options:   "1,2",
				MaxAmount: 5,
			},
			`{"1":5}`,
			true,
		},
		{
			"Method Y, Vote on one option with to less amount",
			decrypt.PollMeta{
				Method:    "Y",
				Options:   "1,2",
				MinAmount: 10,
			},
			`{"1":5}`,
			false,
		},
		{
			"Method Y, Vote on many options with to less amount",
			decrypt.PollMeta{
				Method:    "Y",
				Options:   "1,2",
				MinAmount: 10,
			},
			`{"1":1,"2":1}`,
			false,
		},
		{
			"Method Y, Vote on one option with -1 amount",
			decrypt.PollMeta{
				Method:  "Y",
				Options: "1,2",
			},
			`{"1":-1}`,
			false,
		},
		{
			"Method Y, Vote wrong option",
			decrypt.PollMeta{
				Method:  "Y",
				Options: "1,2",
			},
			`{"5":1}`,
			false,
		},

		// Test Method YN and YNA
		{
			"Method YN, Global Y, Vote Y",
			decrypt.PollMeta{
				Method:    "YN",
				GlobalYes: true,
			},
			`"Y"`,
			true,
		},
		{
			"Method YN, Not Global Y, Vote Y",
			decrypt.PollMeta{
				Method:    "YN",
				GlobalYes: false,
			},
			`"Y"`,
			false,
		},
		{
			"Method YNA, Global N, Vote N",
			decrypt.PollMeta{
				Method:   "YNA",
				GlobalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method YNA, Not Global N, Vote N",
			decrypt.PollMeta{
				Method:    "YNA",
				GlobalYes: false,
			},
			`"N"`,
			false,
		},
		{
			"Method YNA, Y on Option",
			decrypt.PollMeta{
				Method:  "YNA",
				Options: "1,2",
			},
			`{"1":"Y"}`,
			true,
		},
		{
			"Method YNA, N on Option",
			decrypt.PollMeta{
				Method:  "YNA",
				Options: "1,2",
			},
			`{"1":"N"}`,
			true,
		},
		{
			"Method YNA, A on Option",
			decrypt.PollMeta{
				Method:  "YNA",
				Options: "1,2",
			},
			`{"1":"A"}`,
			true,
		},
		{
			"Method YN, A on Option",
			decrypt.PollMeta{
				Method:  "YN",
				Options: "1,2",
			},
			`{"1":"A"}`,
			false,
		},
		{
			"Method YN, Y on wrong Option",
			decrypt.PollMeta{
				Method:  "YN",
				Options: "1,2",
			},
			`{"3":"Y"}`,
			false,
		},
		{
			"Method YNA, Vote on many Options",
			decrypt.PollMeta{
				Method:  "YNA",
				Options: "1,2,3",
			},
			`{"1":"Y","2":"N","3":"A"}`,
			true,
		},
		{
			"Method YNA, Amount on Option",
			decrypt.PollMeta{
				Method:  "YNA",
				Options: "1,2,3",
			},
			`{"1":1}`,
			false,
		},

		// Unknown method
		{
			"Method Unknown",
			decrypt.PollMeta{
				Method: "XXX",
			},
			`"Y"`,
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.meta)
			store.loadData = fmt.Sprintf(`{"key":"ZnVsbC1rZXk=","meta":%s}`, data)
			encrypted := fmt.Sprintf(`enc:{"poll_id":"test/1","votes": %s}`, tt.vote)

			valid, err := d.Validate(context.Background(), "test/1", []byte(encrypted), decrypt.VoteMeta{})
			if err != nil {
				t.Fatalf("validate: %v", err)
			}

			if valid != tt.expectValid {
				t.Errorf("Validate returned %t, expected %t", valid, tt.expectValid)
			}
		})
	}
}
