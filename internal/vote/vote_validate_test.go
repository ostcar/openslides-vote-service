package vote

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestVoteValidate(t *testing.T) {
	for _, tt := range []struct {
		name        string
		poll        pollConfig
		vote        string
		expectValid bool
	}{
		// Test Method Y and N.
		{
			"Method Y, Global Y, Vote Y",
			pollConfig{
				method:    "Y",
				globalYes: true,
			},
			`"Y"`,
			true,
		},
		{
			"Method Y, Vote Y",
			pollConfig{
				method:    "Y",
				globalYes: false,
			},
			`"Y"`,
			false,
		},
		{
			"Method Y, Vote N",
			pollConfig{
				method:   "Y",
				globalNo: false,
			},
			`"N"`,
			false,
		},
		{
			// The poll config is invalid. A poll with method Y should not allow global_no.
			"Method Y, Global N, Vote N",
			pollConfig{
				method:   "Y",
				globalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method N, Global N, Vote N",
			pollConfig{
				method:   "N",
				globalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method Y, Vote Option",
			pollConfig{
				method:  "Y",
				options: []int{1, 2},
			},
			`{"1":1}`,
			true,
		},
		{
			"Method Y, Vote on to many Options",
			pollConfig{
				method:  "Y",
				options: []int{1, 2},
			},
			`{"1":1,"2":1}`,
			false,
		},
		{
			"Method Y, Vote on one option with to high amount",
			pollConfig{
				method:  "Y",
				options: []int{1, 2},
			},
			`{"1":5}`,
			false,
		},
		{
			"Method Y, Vote on many option with to high amount",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2},
				maxAmount:         2,
				maxVotesPerOption: 1,
			},
			`{"1":1,"2":2}`,
			false,
		},
		{
			"Method Y, Vote on one option with correct amount",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2},
				maxAmount:         5,
				maxVotesPerOption: 7,
			},
			`{"1":5}`,
			true,
		},
		{
			"Method Y, Vote on one option with to less amount",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2},
				minAmount:         10,
				maxAmount:         10,
				maxVotesPerOption: 10,
			},
			`{"1":5}`,
			false,
		},
		{
			"Method Y, Vote on many options with to less amount",
			pollConfig{
				method:    "Y",
				options:   []int{1, 2},
				minAmount: 10,
			},
			`{"1":1,"2":1}`,
			false,
		},
		{
			"Method Y, Vote on one option with -1 amount",
			pollConfig{
				method:  "Y",
				options: []int{1, 2},
			},
			`{"1":-1}`,
			false,
		},
		{
			"Method Y, Vote wrong option",
			pollConfig{
				method:  "Y",
				options: []int{1, 2},
			},
			`{"5":1}`,
			false,
		},
		{
			"Method Y and maxVotesPerOption>1, Correct vote",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2, 3, 4},
				maxAmount:         6,
				maxVotesPerOption: 3,
			},
			`{"1":2,"2":0,"3":3,"4":1}`,
			true,
		},
		{
			"Method Y and maxVotesPerOption>1, Too many votes on one option",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2},
				maxAmount:         4,
				maxVotesPerOption: 2,
			},
			`{"1":3,"2":1}`,
			false,
		},
		{
			"Method Y and maxVotesPerOption>1, Too many votes in total",
			pollConfig{
				method:            "Y",
				options:           []int{1, 2},
				maxAmount:         3,
				maxVotesPerOption: 2,
			},
			`{"1":2,"2":2}`,
			false,
		},

		// Test Method YN and YNA
		{
			"Method YN, Global Y, Vote Y",
			pollConfig{
				method:    "YN",
				globalYes: true,
			},
			`"Y"`,
			true,
		},
		{
			"Method YN, Not Global Y, Vote Y",
			pollConfig{
				method:    "YN",
				globalYes: false,
			},
			`"Y"`,
			false,
		},
		{
			"Method YNA, Global N, Vote N",
			pollConfig{
				method:   "YNA",
				globalNo: true,
			},
			`"N"`,
			true,
		},
		{
			"Method YNA, Not Global N, Vote N",
			pollConfig{
				method:    "YNA",
				globalYes: false,
			},
			`"N"`,
			false,
		},
		{
			"Method YNA, Y on Option",
			pollConfig{
				method:  "YNA",
				options: []int{1, 2},
			},
			`{"1":"Y"}`,
			true,
		},
		{
			"Method YNA, N on Option",
			pollConfig{
				method:  "YNA",
				options: []int{1, 2},
			},
			`{"1":"N"}`,
			true,
		},
		{
			"Method YNA, A on Option",
			pollConfig{
				method:  "YNA",
				options: []int{1, 2},
			},
			`{"1":"A"}`,
			true,
		},
		{
			"Method YN, A on Option",
			pollConfig{
				method:  "YN",
				options: []int{1, 2},
			},
			`{"1":"A"}`,
			false,
		},
		{
			"Method YN, Y on wrong Option",
			pollConfig{
				method:  "YN",
				options: []int{1, 2},
			},
			`{"3":"Y"}`,
			false,
		},
		{
			"Method YNA, Vote on many Options",
			pollConfig{
				method:  "YNA",
				options: []int{1, 2, 3},
			},
			`{"1":"Y","2":"N","3":"A"}`,
			true,
		},
		{
			"Method YNA, Amount on Option",
			pollConfig{
				method:  "YNA",
				options: []int{1, 2, 3},
			},
			`{"1":1}`,
			false,
		},

		// Unknown method
		{
			"Method Unknown",
			pollConfig{
				method: "XXX",
			},
			`"Y"`,
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var b ballot
			if err := json.Unmarshal([]byte(tt.vote), &b.Value); err != nil {
				t.Fatalf("decoding vote: %v", err)
			}

			err := b.validate(tt.poll)

			if tt.expectValid {
				if err != nil {
					t.Fatalf("Validate returned unexpected error: %v", err)
				}
				return
			}

			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Expected ErrInvalid, got: %v", err)
			}
		})
	}
}
