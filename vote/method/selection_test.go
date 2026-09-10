package method_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/vote/method"
	"github.com/shopspring/decimal"
)

func TestSelectionValidateVote(t *testing.T) {
	for _, tt := range []struct {
		name        string
		config      string
		options     []int
		vote        string
		expectValid bool
	}{
		{
			name:        "Selection invalid json",
			config:      `{}`,
			options:     []int{1, 2},
			vote:        `[0`,
			expectValid: false,
		},
		{
			name:        "Selection",
			config:      `{}`,
			options:     []int{1, 2},
			vote:        `[1]`,
			expectValid: true,
		},
		{
			name:        "Selection same value multiple times",
			config:      `{}`,
			options:     []int{1, 2},
			vote:        `[1,1]`,
			expectValid: false,
		},
		{
			name:        "Selection unknown key",
			config:      `{}`,
			options:     []int{1, 2},
			vote:        `[3]`,
			expectValid: false,
		},
		{
			name:        "Selection max_options_amount",
			config:      `{"max_options_amount":1}`,
			options:     []int{1, 2},
			vote:        `[1]`,
			expectValid: true,
		},
		{
			name:        "Selection max_options_amount too many",
			config:      `{"max_options_amount":1}`,
			options:     []int{1, 2},
			vote:        `[1,2]`,
			expectValid: false,
		},
		{
			name:        "Selection min_options_amount",
			config:      `{"min_options_amount":1}`,
			options:     []int{1, 2},
			vote:        `[1]`,
			expectValid: true,
		},
		{
			name:        "Selection min_options_amount too few",
			config:      `{"min_options_amount":2}`,
			options:     []int{1, 2},
			vote:        `[1]`,
			expectValid: false,
		},
		{
			name:        "min_options_amount too few but allow_abstain",
			config:      `{"min_options_amount":2,"allow_abstain":true}`,
			options:     []int{1, 2},
			vote:        `[]`,
			expectValid: true,
		},
		{
			name:        "min_options_amount too few but not allow_abstain",
			config:      `{"min_options_amount":2,"allow_abstain":false}`,
			options:     []int{1, 2},
			vote:        `[]`,
			expectValid: false,
		},
		{
			name:        "min_options_amount == 0 with no abstain",
			config:      `{"min_options_amount":0,"allow_abstain":false}`,
			options:     []int{1, 2},
			vote:        `{}`,
			expectValid: false,
		},
		{
			name:        "Selection nota",
			config:      `{"min_options_amount":2,"allow_nota":true}`,
			options:     []int{1, 2},
			vote:        `"nota"`,
			expectValid: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := method.SelectionFromJSON(tt.config)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			a.Options = tt.options

			err = a.ValidateBallot(json.RawMessage(tt.vote))

			if err != nil {
				if _, ok := errors.AsType[method.InvalidBallotError](err); !ok {
					t.Errorf("Got unexpected error: %v", err)
				}
			}

			if tt.expectValid {
				if err != nil {
					t.Fatalf("Validate returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Got no validation error")
			}
		})
	}
}

func TestSelectionCreateResult(t *testing.T) {
	for _, tt := range []struct {
		name         string
		method       string
		config       string
		options      []int
		ballots      []method.Ballot
		expectResult string
	}{
		{
			name:    "Selection",
			method:  "selection",
			config:  `{}`,
			options: []int{1, 2, 3},
			ballots: []method.Ballot{
				{Value: `[1,2]`},
				{Value: `[2,3]`},
				{Value: `[3]`, Weight: decimal.NewFromInt(5)},
			},
			expectResult: `{"1":"1","2":"2","3":"6","total_ballots":3}`,
		},
		{
			name:    "Selection abstain",
			method:  "selection",
			config:  `{}`,
			options: []int{1, 2, 3},
			ballots: []method.Ballot{
				{Value: `[1,2]`},
				{Value: `[]`},
				{Value: `[]`, Weight: decimal.NewFromInt(5)},
			},
			expectResult: `{"1":"1","2":"1","abstain":"6","total_ballots":3}`,
		},
		{
			name:    "Selection nota",
			method:  "selection",
			config:  `{"allow_nota":true}`,
			options: []int{1, 2, 3},
			ballots: []method.Ballot{
				{Value: `[1,2]`},
				{Value: `"nota"`},
				{Value: `"nota"`, Weight: decimal.NewFromInt(5)},
			},
			expectResult: `{"1":"1","2":"1","nota":"6","total_ballots":3}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := method.SelectionFromJSON(tt.config)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}
			a.Options = tt.options

			result, err := a.Result(tt.ballots)
			if err != nil {
				t.Fatalf("CreateResult: %v", err)
			}

			if string(result) != tt.expectResult {
				t.Errorf("Got: %s, expected %s", result, tt.expectResult)
			}
		})
	}
}
