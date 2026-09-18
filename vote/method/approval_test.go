package method_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/OpenSlides/openslides-vote-service/vote/method"
)

func TestApprovalValidateVote(t *testing.T) {
	for _, tt := range []struct {
		name        string
		method      string
		config      string
		vote        string
		expectValid bool
	}{
		{
			name:        "Approval: Vote Yes",
			method:      "approval",
			config:      "",
			vote:        `"Yes"`,
			expectValid: true,
		},
		{
			name:        "Approval: unknown string",
			method:      "approval",
			config:      "",
			vote:        `"Y"`,
			expectValid: false,
		},
		{
			name:        "Approval: Abstain",
			method:      "approval",
			config:      "",
			vote:        `"Abstain"`,
			expectValid: true,
		},
		{
			name:        "Approval: Abstain deactivated",
			method:      "approval",
			config:      `{"allow_abstain": false}`,
			vote:        `"Abstain"`,
			expectValid: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := method.ApprovalFromJson(tt.config)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

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

func TestApprovalCreateResult(t *testing.T) {
	for _, tt := range []struct {
		name         string
		config       string
		ballots      []method.Ballot
		allowEmpty   bool
		expectResult string
	}{
		{
			name:   "Approval",
			config: "",
			ballots: []method.Ballot{
				{Value: `"Yes"`},
				{Value: `"Yes"`},
				{Value: `"No"`},
			},
			allowEmpty:   false,
			expectResult: `{"no":"1","total_ballots":3,"yes":"2"}`,
		},
		{
			name:   "Invalid",
			config: "",
			ballots: []method.Ballot{
				{Value: `"Yes"`},
				{Value: `"Yes"`},
				{Value: `"No"`},
				{Value: `"ABC"`},
			},
			allowEmpty:   false,
			expectResult: `{"invalid":1,"no":"1","total_ballots":4,"yes":"2"}`,
		},
		{
			name:   "AllowEmpty",
			config: "",
			ballots: []method.Ballot{
				{Value: `"Yes"`},
				{Value: `"Yes"`},
				{Value: `"No"`},
				{Value: `"ABC"`},
				{Value: ``},
				{Value: `null`},
			},
			allowEmpty:   true,
			expectResult: `{"empty":"2","invalid":1,"no":"1","total_ballots":6,"yes":"2"}`,
		},
		{
			name:   "Empty not allowed",
			config: "",
			ballots: []method.Ballot{
				{Value: `"Yes"`},
				{Value: `"Yes"`},
				{Value: `"No"`},
				{Value: `"ABC"`},
				{Value: ``},
				{Value: `null`},
			},
			allowEmpty:   false,
			expectResult: `{"invalid":3,"no":"1","total_ballots":6,"yes":"2"}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := method.ApprovalFromJson(tt.config)
			if err != nil {
				t.Fatalf("Error: %v", err)
			}

			result, err := a.Result(tt.ballots, tt.allowEmpty)
			if err != nil {
				t.Fatalf("CreateResult: %v", err)
			}

			if string(result) != tt.expectResult {
				t.Errorf("Got: %s, expected %s", result, tt.expectResult)
			}
		})
	}
}
