package method

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/dstypes"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// Selection represents a selection vote method configuration.
type Selection struct {
	Options          []int              `json:"options"`
	MaxOptionsAmount dsfetch.Maybe[int] `json:"max_options_amount"`
	MinOptionsAmount dsfetch.Maybe[int] `json:"min_options_amount"`
	AllowNota        bool               `json:"allow_nota"`
	AllowAbstain     bool               `json:"allow_abstain"`
}

// SelectionFromJSON parses the given JSON config into a Selection struct.
func SelectionFromJSON(config string) (*Selection, error) {
	var cfg Selection
	cfg.AllowAbstain = true
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Name returns the name of the selection method.
func (s Selection) Name() string {
	return "selection"
}

// RequireOptions returns true, as selection requires options.
func (Selection) RequireOptions() bool {
	return true
}

// SelectionFromDsModels converts a dsmodels.PollConfigSelection into a Selection struct.
func SelectionFromDsModels(configDB dsmodels.PollConfigSelection, optionIDs []int) Selection {
	return Selection{
		Options:          optionIDs,
		MaxOptionsAmount: maybeZeroIsNull(configDB.MaxOptionsAmount),
		MinOptionsAmount: maybeZeroIsNull(configDB.MinOptionsAmount),
		AllowNota:        configDB.AllowNota,
		AllowAbstain:     configDB.AllowAbstain,
	}
}

type selectionConfig struct {
	AllowNota             *bool   `json:"allow_nota"`
	DisplayChart          *string `json:"display_chart"`
	StrikeOut             *bool   `json:"strike_out"`
	MaxOptionsAmount      *int    `json:"max_options_amount"`
	MinOptionsAmount      *int    `json:"min_options_amount"`
	AllowAbstain          *bool   `json:"allow_abstain"`
	OneHundredPercentBase *string `json:"onehundred_percent_base"`
	RequiredMajority      *string `json:"required_majority"`
}

func selectionConfigForCreate(config json.RawMessage, optionAmount int) (*selectionConfig, error) {
	var cfg selectionConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if cfg.AllowNota == nil {
		cfg.AllowNota = new(bool)
	}
	if cfg.DisplayChart == nil {
		cfg.DisplayChart = new(string)
	}
	if cfg.StrikeOut == nil {
		cfg.StrikeOut = new(bool)
	}
	if cfg.MaxOptionsAmount == nil {
		cfg.MaxOptionsAmount = new(int)
	}
	if *cfg.MaxOptionsAmount != 0 && *cfg.MaxOptionsAmount > optionAmount {
		return nil, invalidConfig("Value of max_options_amount can not be higher then the amount of available options")
	}
	if cfg.MinOptionsAmount == nil {
		cfg.MinOptionsAmount = new(int)
	}
	if *cfg.MinOptionsAmount > *cfg.MaxOptionsAmount {
		return nil, invalidConfig("Value of min_options_amount has to be lower then max_options_amount")
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

func selectionConfigForUpdate(config json.RawMessage, state dstypes.Poll_State, optionAmount int, oldConfig dsmodels.PollConfigSelection) (*selectionConfig, error) {
	var cfg selectionConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Method_config has to be valid json")
	}

	if state != dstypes.Poll_StateCreated {
		if cfg.AllowNota != nil {
			return nil, invalidConfig("Field allow_nota is not allowed to update in poll state %s", state)
		}
		if cfg.AllowAbstain != nil {
			return nil, invalidConfig("Field allow_abstain is not allowed to update in poll state %s", state)
		}
		if cfg.MaxOptionsAmount != nil {
			return nil, invalidConfig("Field max_options_amount is not allowed to update in poll state %s", state)
		}
		if cfg.MinOptionsAmount != nil {
			return nil, invalidConfig("Field min_options_amount is not allowed to update in poll state %s", state)
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
	if max != 0 && max > optionAmount {
		return nil, invalidConfig("Value of max_options_amount can not be higher then the amount of available options")
	}

	return &cfg, nil
}

func selectionConfigCreate(ctx context.Context, tx pgx.Tx, optionAmount int, config json.RawMessage) (string, error) {
	cfg, err := selectionConfigForCreate(config, optionAmount)
	if err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	var configID int
	sql := `INSERT INTO poll_config_selection
	(allow_nota, display_chart, strike_out, max_options_amount, min_options_amount, allow_abstain, onehundred_percent_base, required_majority)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	RETURNING id;`
	if err := tx.QueryRow(
		ctx,
		sql,
		cfg.AllowNota,
		cfg.DisplayChart,
		cfg.StrikeOut,
		cfg.MaxOptionsAmount,
		cfg.MinOptionsAmount,
		cfg.AllowAbstain,
		cfg.OneHundredPercentBase,
		cfg.RequiredMajority,
	).Scan(&configID); err != nil {
		return "", fmt.Errorf("save selection config: %w", err)
	}

	return fmt.Sprintf("poll_config_selection/%d", configID), nil
}

func selectionConfigUpdate(ctx context.Context, ds flow.Getter, tx pgx.Tx, id int, pollState dstypes.Poll_State, optionAmount int, config json.RawMessage) error {
	oldConfig, err := dsmodels.New(ds).PollConfigSelection(id).First(ctx)
	cfg, err := selectionConfigForUpdate(config, pollState, optionAmount, oldConfig)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sql := `
	UPDATE poll_config_selection
	SET
		allow_nota = COALESCE($2, allow_nota),
		allow_abstain = COALESCE($3, allow_abstain),
		display_chart = COALESCE($4, display_chart),
		strike_out = COALESCE($5, strike_out),
		max_options_amount = COALESCE($6, max_options_amount),
		min_options_amount = COALESCE($7, min_options_amount),
		onehundred_percent_base = COALESCE($8, onehundred_percent_base),
		required_majority = COALESCE($9, required_majority)
	WHERE id = $1;`

	res, err := tx.Exec(
		ctx,
		sql,
		id,
		cfg.AllowNota,
		cfg.AllowAbstain,
		cfg.DisplayChart,
		cfg.StrikeOut,
		cfg.MaxOptionsAmount,
		cfg.MinOptionsAmount,
		cfg.OneHundredPercentBase,
		cfg.RequiredMajority,
	)
	if err != nil {
		return fmt.Errorf("update approval config: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("approval config %d not found", id)
	}

	return nil
}

// ValidateBallot validates a ballot.
func (s Selection) ValidateBallot(vote json.RawMessage) error {
	var choice []int
	if err := json.Unmarshal(vote, &choice); err != nil {
		if s.AllowNota && strings.ToLower(string(vote)) == `"nota"` {
			return nil
		}
		return errors.Join(invalidVote("Vote has invalid format"), fmt.Errorf("decoding vote: %w", err))
	}

	if hasDuplicates(choice) {
		return invalidVote("douplicate entries in vote")
	}

	if value, set := s.MaxOptionsAmount.Value(); set && len(choice) > value {
		return invalidVote("too many options")
	}

	if !s.AllowAbstain && len(choice) == 0 {
		return invalidVote("abstain not allowed")
	}

	if value, set := s.MinOptionsAmount.Value(); set && len(choice) < value {
		if !(s.AllowAbstain && len(choice) == 0) {
			return invalidVote("too few options")
		}

	}

	for _, option := range choice {
		if !slices.Contains(s.Options, option) {
			return invalidVote("unknown option id %d", option)
		}
	}

	return nil
}

// Result calculates the result.
func (s Selection) Result(votes []Ballot) (string, error) {
	return iterateValues(s, votes, func(value string, weight decimal.Decimal, result map[string]decimal.Decimal) error {
		var votedOptions []int
		if err := json.Unmarshal([]byte(value), &votedOptions); err != nil {
			if s.AllowNota && strings.ToLower(value) == `"nota"` {
				result[keyNota] = result[keyNota].Add(weight)
				return nil
			}
			return fmt.Errorf("invalid options `%s`: %w", value, err)
		}

		for _, votedOption := range votedOptions {
			result[strconv.Itoa(votedOption)] = result[strconv.Itoa(votedOption)].Add(weight)
		}

		if len(votedOptions) == 0 {
			result[keyAbstain] = result[keyAbstain].Add(weight)
		}

		return nil
	})
}
