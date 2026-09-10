package method

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/dstypes"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// RatingApproval represents the poll method rating_approval.
type RatingApproval struct {
	Options          []int              `json:"options"`
	MaxOptionsAmount dsfetch.Maybe[int] `json:"max_options_amount"`
	MinOptionsAmount dsfetch.Maybe[int] `json:"min_options_amount"`
	MaxYesAmount     dsfetch.Maybe[int] `json:"max_yes_amount"`
	AllowAbstain     bool               `json:"allow_abstain"`
}

// RatingApprovalFromJson parses the given JSON config into a RatingApproval struct.
func RatingApprovalFromJson(config string) (*RatingApproval, error) {
	var cfg RatingApproval
	cfg.AllowAbstain = true
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Name returns the name of the rating approval method.
func (ra RatingApproval) Name() string {
	return "rating_approval"
}

// RequireOptions returns true, as rating approval requires options.
func (RatingApproval) RequireOptions() bool {
	return true
}

// RatingApprovalFromDsModels converts a PollConfigRatingApproval to a RatingApproval struct.
func RatingApprovalFromDsModels(configDB dsmodels.PollConfigRatingApproval, optionIDs []int) *RatingApproval {
	return &RatingApproval{
		Options:          optionIDs,
		MaxOptionsAmount: maybeZeroIsNull(configDB.MaxOptionsAmount),
		MinOptionsAmount: maybeZeroIsNull(configDB.MinOptionsAmount),
		MaxYesAmount:     maybeZeroIsNull(configDB.MaxYesAmount),
		AllowAbstain:     configDB.AllowAbstain,
	}
}

type ratingApprovalConfig struct {
	MaxOptionsAmount      *int    `json:"max_options_amount"`
	MinOptionsAmount      *int    `json:"min_options_amount"`
	MaxYesAmount          *int    `json:"max_yes_amount"`
	AllowAbstain          *bool   `json:"allow_abstain"`
	OneHundredPercentBase *string `json:"onehundred_percent_base"`
	RequiredMajority      *string `json:"required_majority"`
}

func ratingApprovalConfigForCreate(config json.RawMessage, optionAmount int) (*ratingApprovalConfig, error) {
	var cfg ratingApprovalConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if cfg.MaxOptionsAmount == nil {
		cfg.MaxOptionsAmount = new(int)
	}
	if cfg.MinOptionsAmount == nil {
		cfg.MinOptionsAmount = new(int)
	}
	if *cfg.MinOptionsAmount > *cfg.MaxOptionsAmount {
		return nil, invalidConfig("Value of min_options_amount has to be lower then max_options_amount")
	}
	if *cfg.MaxOptionsAmount > optionAmount {
		return nil, invalidConfig("Value of max_options_amount can not be higher then the amount of available options")
	}
	if cfg.MaxYesAmount == nil {
		cfg.MaxYesAmount = new(int)
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

func ratingApprovalConfigForUpdate(config json.RawMessage, state dstypes.Poll_State, optionAmount int, oldConfig dsmodels.PollConfigRatingApproval) (*ratingApprovalConfig, error) {
	var cfg ratingApprovalConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if state != dstypes.Poll_StateCreated {
		if cfg.AllowAbstain != nil {
			return nil, invalidConfig("Field allow_abstain is not allowed to update in poll state %s", state)
		}
		if cfg.MaxOptionsAmount != nil {
			return nil, invalidConfig("Field max_options_amount is not allowed to update in poll state %s", state)
		}
		if cfg.MinOptionsAmount != nil {
			return nil, invalidConfig("Field min_options_amount is not allowed to update in poll state %s", state)
		}
		if cfg.MaxYesAmount != nil {
			return nil, invalidConfig("Field max_yes_amount is not allowed to update in poll state %s", state)
		}
	}

	min := oldConfig.MinOptionsAmount
	if cfg.MinOptionsAmount != nil {
		min = *cfg.MinOptionsAmount
	}
	max := oldConfig.MaxOptionsAmount
	if cfg.MaxOptionsAmount != nil {
		max = *cfg.MaxOptionsAmount
	}
	if (cfg.MinOptionsAmount != nil || cfg.MaxOptionsAmount != nil) && min > max {
		return nil, invalidConfig("Field min_options_amount must be less than or equal to max_options_amount")
	}
	if max > optionAmount {
		return nil, invalidConfig("Value of max_options_amount can not be higher then the amount of available options")
	}

	return &cfg, nil
}

func ratingApprovalConfigCreate(ctx context.Context, tx pgx.Tx, optionAmount int, config json.RawMessage) (string, error) {
	cfg, err := ratingApprovalConfigForCreate(config, optionAmount)
	if err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	var configID int
	sql := `
	INSERT INTO poll_config_rating_approval
	(max_options_amount, min_options_amount, max_yes_amount, allow_abstain, onehundred_percent_base, required_majority)
	VALUES ($1, $2, $3, $4, $5, $6)
	RETURNING id;`
	if err := tx.QueryRow(
		ctx,
		sql,
		cfg.MaxOptionsAmount,
		cfg.MinOptionsAmount,
		cfg.MaxYesAmount,
		cfg.AllowAbstain,
		cfg.OneHundredPercentBase,
		cfg.RequiredMajority,
	).Scan(&configID); err != nil {
		return "", fmt.Errorf("save ratingApproval config: %w", err)
	}

	return fmt.Sprintf("poll_config_rating_approval/%d", configID), nil
}

func ratingApprovalConfigUpdate(ctx context.Context, ds flow.Getter, tx pgx.Tx, id int, pollState dstypes.Poll_State, optionAmount int, config json.RawMessage) error {
	oldConfig, err := dsmodels.New(ds).PollConfigRatingApproval(id).First(ctx)
	cfg, err := ratingApprovalConfigForUpdate(config, pollState, optionAmount, oldConfig)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sql := `
	UPDATE poll_config_rating_approval
	SET
		max_options_amount = COALESCE($2, max_options_amount),
		min_options_amount = COALESCE($3, min_options_amount),
		max_yes_amount = COALESCE($4, max_yes_amount),
		allow_abstain = COALESCE($5, allow_abstain),
		onehundred_percent_base = COALESCE($6, onehundred_percent_base),
		required_majority = COALESCE($7, required_majority)
	WHERE id = $1;`

	res, err := tx.Exec(ctx, sql, id, cfg.MaxOptionsAmount, cfg.MinOptionsAmount, cfg.MaxYesAmount, cfg.AllowAbstain, cfg.OneHundredPercentBase, cfg.RequiredMajority)
	if err != nil {
		return fmt.Errorf("update approval config: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("approval config %d not found", id)
	}

	return nil
}

// ValidateBallot validates the given ballot.
func (ra RatingApproval) ValidateBallot(vote json.RawMessage) error {
	var choice map[int]json.RawMessage
	if err := json.Unmarshal(vote, &choice); err != nil {
		return errors.Join(invalidVote("Vote has invalid format"), fmt.Errorf("decoding vote: %w", err))
	}

	if value, set := ra.MaxOptionsAmount.Value(); set && len(choice) > value {
		return invalidVote("too many options")
	}

	if value, set := ra.MinOptionsAmount.Value(); set && len(choice) < value {
		return invalidVote("too few options")
	}

	maxYesAmount, maxYesSet := ra.MaxYesAmount.Value()

	var countYes int
	for option, choice := range choice {
		if !slices.Contains(ra.Options, option) {
			return invalidVote("unknown option id %d", option)
		}

		approval := &Approval{AllowAbstain: ra.AllowAbstain}
		if err := approval.ValidateBallot(choice); err != nil {
			return fmt.Errorf("validating option id %d: %w", option, err)
		}

		if maxYesSet && strings.ToLower(string(choice)) == `"yes"` {
			countYes += 1
		}
	}

	if maxYesSet && countYes > maxYesAmount {
		return invalidVote("to many yes votes. Got %d votes, only %d allowed.", maxYesAmount, maxYesAmount)
	}

	return nil
}

// Result calculates the result.
func (ra RatingApproval) Result(votes []Ballot) (string, error) {
	result := make(map[string]map[string]decimal.Decimal)
	invalid := 0
	var abstain decimal.Decimal

	for _, vote := range votes {
		if err := ra.ValidateBallot(json.RawMessage(vote.Value)); err != nil {
			if _, ok := errors.AsType[InvalidBallotError](err); ok {
				invalid++
				continue
			}
			return "", fmt.Errorf("validating vote: %w", err)
		}

		weight := vote.Weight
		if vote.Weight.IsZero() {
			weight = decimal.NewFromInt(1)
		}

		var votedOptions map[string]json.RawMessage
		if err := json.Unmarshal([]byte(vote.Value), &votedOptions); err != nil {
			return "", fmt.Errorf("invalid options `%s`: %w", vote.Value, err)
		}

		if len(votedOptions) == 0 {
			abstain = abstain.Add(weight)
			continue
		}

		for option, value := range votedOptions {
			if _, ok := result[option]; !ok {
				result[option] = make(map[string]decimal.Decimal)
			}

			switch strings.ToLower(string(value)) {
			case `"yes"`:
				result[option]["yes"] = result[option]["yes"].Add(weight)
			case `"no"`:
				result[option]["no"] = result[option]["no"].Add(weight)
			case `"abstain"`:
				result[option]["abstain"] = result[option]["abstain"].Add(weight)
			}
		}
	}

	encodedResult, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode result: %w", err)
	}
	withInvalid, err := addExtra(encodedResult, len(votes), invalid, abstain)
	if err != nil {
		return "", fmt.Errorf("add invalid and abstain: %w", err)
	}
	return string(withInvalid), nil
}

func addExtra(result []byte, totalBallots, invalid int, abstain decimal.Decimal) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(result, &data); err != nil {
		return nil, err
	}

	if invalid != 0 {
		data[keyInvalid] = invalid
	}

	if !abstain.IsZero() {
		data[keyAbstain] = abstain
	}

	data[keyTotalBallots] = totalBallots

	return json.Marshal(data)
}
