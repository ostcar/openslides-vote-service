package method

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/dstypes"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// RatingScore represents a rating score method.
type RatingScore struct {
	Options           []int              `json:"options"`
	MaxOptionsAmount  dsfetch.Maybe[int] `json:"max_options_amount"`
	MinOptionsAmount  dsfetch.Maybe[int] `json:"min_options_amount"`
	MaxVotesPerOption dsfetch.Maybe[int] `json:"max_votes_per_option"`
	MaxVoteSum        dsfetch.Maybe[int] `json:"max_vote_sum"`
	MinVoteSum        dsfetch.Maybe[int] `json:"min_vote_sum"`
	AllowAbstain      bool               `json:"allow_abstain"`
}

// RatingScoreFromJson parses the given JSON config into a RatingScore struct.
func RatingScoreFromJson(config string) (*RatingScore, error) {
	var cfg RatingScore
	cfg.AllowAbstain = true
	if err := json.Unmarshal([]byte(config), &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Name returns the name of the rating score method.
func (rs RatingScore) Name() string {
	return "rating_score"
}

// RequireOptions returns true, as rating approval requires options.
func (RatingScore) RequireOptions() bool {
	return true
}

// RatingScoreFromDsModels converts a dsmodels.PollConfigRatingScore to a RatingScore.
func RatingScoreFromDsModels(configDB dsmodels.PollConfigRatingScore, optionIDs []int) RatingScore {
	return RatingScore{
		Options:           optionIDs,
		MaxOptionsAmount:  maybeZeroIsNull(configDB.MaxOptionsAmount),
		MinOptionsAmount:  maybeZeroIsNull(configDB.MinOptionsAmount),
		MaxVotesPerOption: maybeZeroIsNull(configDB.MaxVotesPerOption),
		MaxVoteSum:        maybeZeroIsNull(configDB.MaxVoteSum),
		MinVoteSum:        maybeZeroIsNull(configDB.MinVoteSum),
		AllowAbstain:      configDB.AllowAbstain,
	}
}

type ratingScoreConfig struct {
	MaxOptionsAmount      *int    `json:"max_options_amount"`
	MinOptionsAmount      *int    `json:"min_options_amount"`
	MaxVotesPerOption     *int    `json:"max_votes_per_option"`
	MaxVoteSum            *int    `json:"max_vote_sum"`
	MinVoteSum            *int    `json:"min_vote_sum"`
	AllowAbstain          *bool   `json:"allow_abstain"`
	OneHundredPercentBase *string `json:"onehundred_percent_base"`
	RequiredMajority      *string `json:"required_majority"`
}

func ratingScoreForCreate(config json.RawMessage, optionAmount int) (*ratingScoreConfig, error) {
	var cfg ratingScoreConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, invalidConfig("Field method_config has to be valid json")
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
	if cfg.MaxVotesPerOption == nil {
		cfg.MaxVotesPerOption = new(int)
	}
	if cfg.MaxVoteSum == nil {
		cfg.MaxVoteSum = new(int)
	}
	if cfg.MinVoteSum == nil {
		cfg.MinVoteSum = new(int)
	}
	if *cfg.MinVoteSum > *cfg.MaxVoteSum {
		return nil, invalidConfig("Value of min_vote_sum has to be lower then max_vote_sum")
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

func ratingScoreConfigForUpdate(config json.RawMessage, state dstypes.Poll_State, optionAmount int, oldConfig dsmodels.PollConfigRatingScore) (*ratingScoreConfig, error) {
	var cfg ratingScoreConfig
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
		if cfg.MaxVotesPerOption != nil {
			return nil, invalidConfig("Field max_votes_per_option is not allowed to update in poll state %s", state)
		}
		if cfg.MaxVoteSum != nil {
			return nil, invalidConfig("Field max_vote_sum is not allowed to update in poll state %s", state)
		}
		if cfg.MinVoteSum != nil {
			return nil, invalidConfig("Field min_vote_sum is not allowed to update in poll state %s", state)
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

	min = oldConfig.MinVoteSum
	if cfg.MinVoteSum != nil {
		min = *cfg.MinVoteSum
	}
	max = oldConfig.MaxVoteSum
	if cfg.MaxVoteSum != nil {
		max = *cfg.MaxVoteSum
	}
	if (cfg.MinVoteSum != nil || cfg.MaxVoteSum != nil) && min > max {
		return nil, invalidConfig("Field min_vote_sum must be less than or equal to max_vote_sum")
	}

	return &cfg, nil
}

func ratingScoreConfigCreate(ctx context.Context, tx pgx.Tx, optionAmount int, config json.RawMessage) (string, error) {
	cfg, err := ratingScoreForCreate(config, optionAmount)
	if err != nil {
		return "", fmt.Errorf("parse config: %w", err)
	}

	var configID int
	sql := `INSERT INTO poll_config_rating_score
	(max_options_amount, min_options_amount, max_votes_per_option, max_vote_sum, min_vote_sum, allow_abstain, onehundred_percent_base, required_majority)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	RETURNING id;`
	if err := tx.QueryRow(
		ctx,
		sql,
		cfg.MaxOptionsAmount,
		cfg.MinOptionsAmount,
		cfg.MaxVotesPerOption,
		cfg.MaxVoteSum,
		cfg.MinVoteSum,
		cfg.AllowAbstain,
		cfg.OneHundredPercentBase,
		cfg.RequiredMajority,
	).Scan(&configID); err != nil {
		return "", fmt.Errorf("save rating_score config: %w", err)
	}

	return fmt.Sprintf("poll_config_rating_score/%d", configID), nil
}

func ratingScoreConfigUpdate(ctx context.Context, ds flow.Getter, tx pgx.Tx, id int, pollState dstypes.Poll_State, optionAmount int, config json.RawMessage) error {
	oldConfig, err := dsmodels.New(ds).PollConfigRatingScore(id).First(ctx)
	cfg, err := ratingScoreConfigForUpdate(config, pollState, optionAmount, oldConfig)
	if err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sql := `
	UPDATE poll_config_rating_score
	SET
		max_options_amount = COALESCE($2, max_options_amount),
		min_options_amount = COALESCE($3, min_options_amount),
		max_votes_per_option = COALESCE($4, max_votes_per_option),
		max_vote_sum = COALESCE($5, max_vote_sum),
		min_vote_sum = COALESCE($6, min_vote_sum),
		allow_abstain = COALESCE($7, allow_abstain),
		onehundred_percent_base = COALESCE($8, onehundred_percent_base),
		required_majority = COALESCE($9, required_majority)
	WHERE id = $1;`

	res, err := tx.Exec(
		ctx,
		sql,
		id,
		cfg.MaxOptionsAmount,
		cfg.MinOptionsAmount,
		cfg.MaxVotesPerOption,
		cfg.MaxVoteSum,
		cfg.MinVoteSum,
		cfg.AllowAbstain,
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

// ValidateBallot validates the given ballot.
func (rs RatingScore) ValidateBallot(vote json.RawMessage) error {
	var choice map[int]int
	if err := json.Unmarshal(vote, &choice); err != nil {
		return errors.Join(invalidVote("Vote has invalid format"), fmt.Errorf("decoding vote: %w", err))
	}

	if value, set := rs.MaxOptionsAmount.Value(); set && len(choice) > value {
		return invalidVote("too many options")
	}

	if value, set := rs.MinOptionsAmount.Value(); set && len(choice) < value {
		if !(rs.AllowAbstain && len(choice) == 0) {
			return invalidVote("too few options")
		}
	}

	var sum int
	for option, choice := range choice {
		if !slices.Contains(rs.Options, option) {
			return invalidVote("unknown option id %d", option)
		}

		if choice < 0 {
			return invalidVote("negative value for option")
		}

		if value, set := rs.MaxVotesPerOption.Value(); set {
			if choice > value {
				return invalidVote("too many votes for option")
			}
		}
		sum += choice
	}

	if value, set := rs.MaxVoteSum.Value(); set && sum > value {
		return invalidVote("too many votes")
	}

	if value, set := rs.MinVoteSum.Value(); set && sum < value {
		if !(rs.AllowAbstain && len(choice) == 0) {
			return invalidVote("too few votes")
		}
	}

	return nil
}

// Result calculates the result.
func (rs RatingScore) Result(votes []Ballot) (string, error) {
	return iterateValues(rs, votes, func(value string, weight decimal.Decimal, result map[string]decimal.Decimal) error {
		var votedOptions map[string]int
		if err := json.Unmarshal([]byte(value), &votedOptions); err != nil {
			return fmt.Errorf("invalid options `%s`: %w", value, err)
		}

		for votedOption, value := range votedOptions {
			voteWithFactor := weight.Mul(decimal.NewFromInt(int64(value)))
			result[votedOption] = result[votedOption].Add(voteWithFactor)
		}

		if len(votedOptions) == 0 {
			result[keyAbstain] = result[keyAbstain].Add(weight)
		}

		return nil
	})
}
