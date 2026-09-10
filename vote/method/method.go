package method

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/dstypes"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"
)

// Ballot contains the relevant fields to calculate a vote result. It is simular
// to dsmodels.PollBallot but not with its functionality.
type Ballot struct {
	Weight decimal.Decimal
	Value  string
	Split  bool
}

// Method is an interface to handle the method of a poll.
type Method interface {
	Name() string
	ValidateBallot(ballot json.RawMessage) error
	Result(votes []Ballot) (string, error)
	RequireOptions() bool
}

// ResolveMethod returns the method object for an poll.
func ResolveMethod(ctx context.Context, getter flow.Getter, configStr string, optionIDs []int) (Method, error) {
	configCollection, configIDStr, found := strings.Cut(configStr, "/")
	if !found {
		return nil, fmt.Errorf("invalid config_id: %s", configStr)
	}

	configID, err := strconv.Atoi(configIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid config_id. Second part is not a number: %s", configStr)
	}

	dsm := dsmodels.New(getter)

	switch configCollection {
	case "poll_config_approval":
		configDB, err := dsm.PollConfigApproval(configID).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching poll_config_approval: %w", err)
		}

		return ApprovalFromDsModels(configDB), nil

	case "poll_config_selection":
		configDB, err := dsm.PollConfigSelection(configID).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching poll_config_selection: %w", err)
		}

		return SelectionFromDsModels(configDB, optionIDs), nil

	case "poll_config_rating_score":
		configDB, err := dsm.PollConfigRatingScore(configID).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching poll_config_rating_score: %w", err)
		}

		return RatingScoreFromDsModels(configDB, optionIDs), nil

	case "poll_config_rating_approval":
		configDB, err := dsm.PollConfigRatingApproval(configID).First(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetching poll_config_rating_approval: %w", err)
		}

		return RatingApprovalFromDsModels(configDB, optionIDs), nil

	default:
		return nil, fmt.Errorf("unknown poll config: %s", configStr)
	}
}

// ConfigCreate saves the configuration for a given vote method.
func ConfigCreate(ctx context.Context, tx pgx.Tx, method string, optionAmount int, config json.RawMessage) (string, error) {
	switch method {
	case Approval{}.Name():
		return approvalConfigCreate(ctx, tx, config)
	case Selection{}.Name():
		return selectionConfigCreate(ctx, tx, optionAmount, config)
	case RatingScore{}.Name():
		return ratingScoreConfigCreate(ctx, tx, optionAmount, config)
	case RatingApproval{}.Name():
		return ratingApprovalConfigCreate(ctx, tx, optionAmount, config)
	default:
		return "", fmt.Errorf("unknown method: %s", method)
	}
}

// ConfigUpdate updates the configuration for a given vote method.
func ConfigUpdate(ctx context.Context, ds flow.Getter, tx pgx.Tx, configID string, pollState dstypes.Poll_State, optionAmount int, config json.RawMessage) error {
	method, id, err := SplitConfigID(configID)
	if err != nil {
		return fmt.Errorf("getting method from config_id: %w", err)
	}

	switch method {
	case Approval{}.Name():
		return approvalConfigUpdate(ctx, tx, id, pollState, config)
	case Selection{}.Name():
		return selectionConfigUpdate(ctx, ds, tx, id, pollState, optionAmount, config)
	case RatingScore{}.Name():
		return ratingScoreConfigUpdate(ctx, ds, tx, id, pollState, optionAmount, config)
	case RatingApproval{}.Name():
		return ratingApprovalConfigUpdate(ctx, ds, tx, id, pollState, optionAmount, config)
	default:
		return fmt.Errorf("unknown method: %s", method)
	}
}

// ConfigDelete deletes the configuration for a given vote method.
func ConfigDelete(ctx context.Context, tx pgx.Tx, configID string) error {
	method, id, err := SplitConfigID(configID)
	if err != nil {
		return fmt.Errorf("getting method from config_id: %w", err)
	}

	var configTable string
	switch method {
	case Approval{}.Name():
		configTable = "poll_config_approval_t"
	case Selection{}.Name():
		configTable = "poll_config_selection_t"
	case RatingScore{}.Name():
		configTable = "poll_config_rating_score_t"
	case RatingApproval{}.Name():
		configTable = "poll_config_rating_approval_t"
	default:
		return fmt.Errorf("unknown config type: %s", method)
	}

	if _, err := tx.Exec(ctx,
		fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, configTable),
		id,
	); err != nil {
		return fmt.Errorf("delete from table %s: %w", configTable, err)
	}

	return nil
}

// RequireOptions returns whether the method type requires options.
//
// At the moment, this is true for `rating_approval`, `rating_score` and
// `selection`. It is false for `approval`.
func RequireOptions(methodStr string) (bool, error) {
	method, err := methodFromString(methodStr)
	if err != nil {
		return false, fmt.Errorf("getting method from string %s: %w", methodStr, err)
	}

	return method.RequireOptions(), nil
}

// MaxOptionsAmount returns the max options amout of the poll config or 0 if not set.
func MaxOptionsAmount(ctx context.Context, ds flow.Getter, configID string) (int, error) {
	method, id, err := SplitConfigID(configID)
	if err != nil {
		return 0, fmt.Errorf("getting method from config_id: %w", err)
	}

	fetch := dsfetch.New(ds)

	var fn func(int) *dsfetch.ValueInt
	switch method {
	case Approval{}.Name():
		return 0, nil
	case Selection{}.Name():
		fn = fetch.PollConfigSelection_MaxOptionsAmount
	case RatingScore{}.Name():
		fn = fetch.PollConfigRatingScore_MaxOptionsAmount
	case RatingApproval{}.Name():
		fn = fetch.PollConfigRatingApproval_MaxOptionsAmount
	default:
		return 0, fmt.Errorf("unknown config type: %s", method)
	}

	v, err := fn(id).Value(ctx)
	if err != nil {
		return 0, fmt.Errorf("getting max options amount: %w", err)
	}
	return v, nil
}

func methodFromString(methodStr string) (Method, error) {
	switch methodStr {
	case Approval{}.Name():
		return &Approval{}, nil
	case Selection{}.Name():
		return &Selection{}, nil
	case RatingScore{}.Name():
		return &RatingScore{}, nil
	case RatingApproval{}.Name():
		return &RatingApproval{}, nil
	default:
		return nil, fmt.Errorf("unknown method: %s", methodStr)
	}
}

const (
	keyAbstain      = "abstain"
	keyNota         = "nota"
	keyInvalid      = "invalid"
	keyTotalBallots = "total_ballots"
)

var reservedOptionNames = []string{keyAbstain, keyNota, keyInvalid, keyTotalBallots}

func addInvalidAndTotalBallots(result []byte, totalBallots, invalid int) ([]byte, error) {
	var data map[string]any
	if err := json.Unmarshal(result, &data); err != nil {
		return nil, err
	}

	if invalid != 0 {
		data[keyInvalid] = invalid
	}
	data[keyTotalBallots] = totalBallots

	return json.Marshal(data)
}

func iterateValues(
	m Method,
	votes []Ballot,
	fn func(value string, weight decimal.Decimal, result map[string]decimal.Decimal) error,
) (string, error) {
	result := make(map[string]decimal.Decimal)
	invalid := 0
	for _, vote := range votes {
		if err := m.ValidateBallot(json.RawMessage(vote.Value)); err != nil {
			if _, ok := errors.AsType[InvalidBallotError](err); ok {
				invalid++
				continue
			}
			return "", fmt.Errorf("validating vote: %w", err)
		}

		factor := vote.Weight
		if factor.IsZero() {
			factor = decimal.NewFromInt(1)
		}

		if err := fn(vote.Value, factor, result); err != nil {
			return "", fmt.Errorf("prcess: %w", err)
		}
	}

	encodedResult, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode result: %w", err)
	}

	withInvalidAndTotalBallots, err := addInvalidAndTotalBallots(encodedResult, len(votes), invalid)
	if err != nil {
		return "", fmt.Errorf("add invalid: %w", err)
	}

	return string(withInvalidAndTotalBallots), nil
}

func hasDuplicates[T comparable](slice []T) bool {
	seen := make(map[T]struct{}, len(slice))
	for _, v := range slice {
		if _, ok := seen[v]; ok {
			return true
		}
		seen[v] = struct{}{}
	}
	return false
}

func maybeZeroIsNull(n int) dsfetch.Maybe[int] {
	if n == 0 {
		return dsfetch.Maybe[int]{}
	}

	return dsfetch.MaybeValue(n)
}

// TODO: Maybe find a way to directly implement this in the maybe type, so pgx
// can understand it.
func maybeNullIsNil(n dsfetch.Maybe[int]) any {
	v, hasValue := n.Value()
	if !hasValue {
		return nil
	}
	return v
}

type invalidConfigError struct {
	msg string
}

func invalidConfig(msg string, a ...any) invalidConfigError {
	return invalidConfigError{msg: fmt.Sprintf(msg, a...)}
}

func (invalidConfigError) Type() string {
	return "invalid_config"
}

func (err invalidConfigError) Error() string {
	if err.msg == "" {
		return "Invalid value for field 'config'"
	}
	return err.msg
}

// InvalidBallotError is returned when the ballot has an invalid format.
type InvalidBallotError struct {
	msg string
}

// Type implements the Typer interface so client gets nice error messages.
func (InvalidBallotError) Type() string {
	return "invalid_ballot"
}

func (err InvalidBallotError) Error() string {
	return err.msg
}

func invalidVote(msg string, a ...any) InvalidBallotError {
	return InvalidBallotError{msg: fmt.Sprintf(msg, a...)}
}

// SplitConfigID returns the method from a config ID.
func SplitConfigID(configID string) (string, int, error) {
	configCollection, rawID, found := strings.Cut(configID, "/")
	if !found {
		return "", 0, fmt.Errorf("poll has an invalid config_id: %s", configID)
	}

	id, err := strconv.Atoi(rawID)
	if err != nil {
		return "", 0, fmt.Errorf("invalid config id: %s", rawID)
	}

	m, found := strings.CutPrefix(configCollection, "poll_config_")
	if !found {
		return "", 0, fmt.Errorf("poll has an unknown poll config: %s", configID)
	}
	return m, id, nil
}
