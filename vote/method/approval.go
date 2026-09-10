package method

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/dstypes"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// Approval represents the poll method approval.
type Approval struct {
	AllowAbstain bool `json:"allow_abstain"`
}

// ApprovalFromJSON parses the given JSON config into an Approval struct.
func ApprovalFromJSON(config string) (*Approval, error) {
	var cfg Approval
	cfg.AllowAbstain = true
	if config == "" {
		return &cfg, nil
	}
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Name returns the name of the approval method.
func (Approval) Name() string {
	return "approval"
}

// RequireOptions returns false, as approval does not require options.
func (Approval) RequireOptions() bool {
	return false
}

// ApprovalFromDsModels converts a PollConfigApproval into an Approval struct.
func ApprovalFromDsModels(configDB dsmodels.PollConfigApproval) *Approval {
	return &Approval{
		AllowAbstain: configDB.AllowAbstain,
	}
}

type approvalConfig struct {
	AllowAbstain          *bool   `json:"allow_abstain"`
	OneHundredPercentBase *string `json:"onehundred_percent_base"`
	RequiredMajority      *string `json:"required_majority"`
}

func approvalConfigForCreate(config json.RawMessage) (*approvalConfig, error) {
	var cfg approvalConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if cfg.AllowAbstain == nil {
		t := true
		cfg.AllowAbstain = &t
	}

	if cfg.OneHundredPercentBase == nil {
		return nil, invalidConfig("Field onehundred_percent_base is required")
	}

	if cfg.RequiredMajority == nil {
		v := "no_majority"
		cfg.RequiredMajority = &v
	}

	return &cfg, nil
}

func approvalConfigForUpdate(config json.RawMessage, state dstypes.Poll_State) (*approvalConfig, error) {
	var cfg approvalConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if state != dstypes.Poll_StateCreated && cfg.AllowAbstain != nil {
		return nil, invalidConfig("Field allow_abstain is not allowed to update in poll state %s", state)
	}

	return &cfg, nil
}

func approvalConfigCreate(ctx context.Context, tx pgx.Tx, config json.RawMessage) (string, error) {
	cfg, err := approvalConfigForCreate(config)
	if err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	var configID int
	sql := `
	INSERT INTO poll_config_approval
	(allow_abstain, onehundred_percent_base, required_majority)
	VALUES ($1, $2, $3)
	RETURNING id;`
	if err := tx.QueryRow(ctx, sql, cfg.AllowAbstain, cfg.OneHundredPercentBase, cfg.RequiredMajority).Scan(&configID); err != nil {
		return "", fmt.Errorf("save approval config: %w", err)
	}

	return fmt.Sprintf("poll_config_approval/%d", configID), nil
}

func approvalConfigUpdate(ctx context.Context, tx pgx.Tx, id int, pollState dstypes.Poll_State, config json.RawMessage) error {
	cfg, err := approvalConfigForUpdate(config, pollState)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sql := `
	UPDATE poll_config_approval
	SET
		allow_abstain = COALESCE($2, allow_abstain),
		onehundred_percent_base = COALESCE($3, onehundred_percent_base),
		required_majority = COALESCE($4, required_majority)
	WHERE id = $1;`

	res, err := tx.Exec(ctx, sql, id, cfg.AllowAbstain, cfg.OneHundredPercentBase, cfg.RequiredMajority)
	if err != nil {
		return fmt.Errorf("update approval config: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("approval config %d not found", id)
	}

	return nil
}

// ValidateBallot validates the given ballot.
func (a *Approval) ValidateBallot(ballot json.RawMessage) error {
	switch strings.ToLower(string(ballot)) {
	case `"yes"`, `"no"`:
		return nil
	case `"abstain"`:
		if !a.AllowAbstain {
			return invalidVote("abstain disabled")
		}
		return nil
	default:
		return invalidVote("Unknown value %s", ballot)
	}
}

// Result calculates the result.
func (a *Approval) Result(ballots []Ballot) (string, error) {
	return iterateValues(a, ballots, func(value string, weight decimal.Decimal, result map[string]decimal.Decimal) error {
		switch strings.ToLower(value) {
		case `"yes"`:
			result["yes"] = result["yes"].Add(weight)
		case `"no"`:
			result["no"] = result["no"].Add(weight)
		case `"abstain"`:
			result["abstain"] = result["abstain"].Add(weight)
		}
		return nil
	})
}
