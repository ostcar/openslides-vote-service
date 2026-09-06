package vote

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dskey"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/OpenSlides/openslides-go/environment"
	"github.com/OpenSlides/openslides-go/history"
	"github.com/OpenSlides/openslides-go/perm"
	"github.com/OpenSlides/openslides-vote-service/vote/method"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/shopspring/decimal"
)

var envVoteSecretKeyFile = environment.NewVariable("VOTE_SECRET_KEY_FILE", "/run/secrets/vote_secret_key", "Path to the secret key for secret polls. The content of the file can be anything.")

// Vote holds the state of the service.
//
// Vote has to be initializes with vote.New().
type Vote struct {
	flow              flow.Flow
	querier           DBQuerier
	gcmForSecretPolls cipher.AEAD
}

// New creates an initializes vote service.
func New(lookup environment.Environmenter, flow flow.Flow, querier DBQuerier) (*Vote, func(context.Context, func(error)), error) {
	key, err := environment.ReadSecret(lookup, envVoteSecretKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read secret key: %w", err)
	}

	hashedKey := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hashedKey[:])
	if err != nil {
		return nil, nil, fmt.Errorf("create cipher for secret polls: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("create GCM for secret polls: %w", err)
	}

	v := &Vote{
		flow:              flow,
		querier:           querier,
		gcmForSecretPolls: gcm,
	}

	bg := func(ctx context.Context, errorHandler func(error)) {
		v.flow.Update(ctx, func(changedData map[dskey.Key][]byte, err error) {
			if err != nil {
				errorHandler(err)
			}

			// This listens on the message bus to see, if a poll got started. If
			// so, it preloads its data. This is only relevant, if a poll gets
			// started on another instance.
			for key, value := range changedData {
				if key.CollectionField() == "poll/state" && string(value) == `"started"` {
					poll, err := dsmodels.New(v.flow).Poll(key.ID()).First(ctx)
					if err != nil {
						errorHandler(fmt.Errorf("Error fetching poll for preload: %w", err))
						continue
					}
					if err := Preload(ctx, dsfetch.New(v.flow), poll.ID, poll.MeetingID); err != nil {
						errorHandler(fmt.Errorf("Error preloading poll: %w", err))
						continue
					}
				}
			}
		})
	}

	return v, bg, nil
}

// Create create a poll, returning the poll id.
func (v *Vote) Create(ctx context.Context, requestUserID int, r io.Reader) (int, error) {
	electronicVotingEnabled, err := dsfetch.New(v.flow).Organization_EnableElectronicVoting(1).Value(ctx)
	if err != nil {
		return 0, fmt.Errorf("fetch organization/1/enable_electronic_voting: %w", err)
	}

	ci, err := parseCreateInput(r, electronicVotingEnabled)
	if err != nil {
		return 0, fmt.Errorf("parsing input: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, ci.MeetingID, ci.ContentObjectID, requestUserID); err != nil {
		return 0, fmt.Errorf("check permissions: %w", err)
	}

	tx, err := v.querier.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	configID, err := method.ConfigCreate(ctx, tx, ci.Method, len(ci.Options), ci.MethodConfig)
	if err != nil {
		return 0, fmt.Errorf("save poll config: %w", err)
	}

	state := "created"
	if ci.Visibility == "manually" {
		state = "finished"
	}

	sql := `INSERT INTO poll_t
		(title, config_id, visibility, state, content_object_id, meeting_id, result, live_voting_enabled, allow_vote_split)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id;`

	var newID int
	if err := tx.QueryRow(
		ctx,
		sql,
		ci.Title,
		configID,
		ci.Visibility,
		state,
		ci.ContentObjectID,
		ci.MeetingID,
		string(ci.Result),
		ci.LiveVotingEnabled,
		ci.AllowVoteSplit,
	).Scan(&newID); err != nil {
		return 0, fmt.Errorf("save poll: %w", err)
	}

	if len(ci.Options) > 0 {
		if err := saveOptions(ctx, tx, newID, ci.OptionType, ci.Options); err != nil {
			return 0, fmt.Errorf("save options: %w", err)
		}
	}

	if len(ci.EntitledGroupIDs) > 0 {
		groupSQL := `
        INSERT INTO nm_group_poll_ids_poll_t (group_id, poll_id)
        SELECT unnest($1::int[]), $2`

		if _, err := tx.Exec(ctx, groupSQL, ci.EntitledGroupIDs, newID); err != nil {
			return 0, fmt.Errorf("insert group-poll relations: %w", err)
		}
	}

	if err := history.OneEntry(ctx, tx, requestUserID, ci.ContentObjectID, ci.MeetingID, "poll created"); err != nil {
		return 0, fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit transaction: %w", err)
	}

	return newID, nil
}

func saveOptions(ctx context.Context, tx pgx.Tx, pollID int, oType string, optionList []json.RawMessage) error {
	if len(optionList) == 0 {
		return nil
	}

	weights := make([]int, len(optionList))
	for i := range optionList {
		weights[i] = i + 1
	}

	switch oType {
	case "text":
		textOptions := make([]string, len(optionList))
		for i, option := range optionList {
			if err := json.Unmarshal(option, &textOptions[i]); err != nil {
				return errors.Join(fmt.Errorf("decode text option: %w", err), MessageError(ErrInvalid, "Invalid option"))
			}
		}

		sql := `INSERT INTO poll_option_t (poll_id, weight, text)
				SELECT $1, unnest($2::int[]), unnest($3::text[]);`
		if _, err := tx.Exec(ctx, sql, pollID, weights, textOptions); err != nil {
			return fmt.Errorf("insert text options: %w", err)
		}

	case "meeting_user":
		contentObjectIDs := make([]string, len(optionList))
		for i, option := range optionList {
			var meetingUserOption int
			if err := json.Unmarshal(option, &meetingUserOption); err != nil {
				return errors.Join(fmt.Errorf("decode meeting_user option: %w", err), MessageError(ErrInvalid, "Invalid option"))
			}
			contentObjectIDs[i] = fmt.Sprintf("meeting_user/%d", meetingUserOption)
		}

		sql := `INSERT INTO poll_option_t (poll_id, weight, content_object_id)
				SELECT $1, unnest($2::int[]), unnest($3::text[]);`
		if _, err := tx.Exec(ctx, sql, pollID, weights, contentObjectIDs); err != nil {
			return fmt.Errorf("insert meeting_user options: %w", err)
		}

	default:
		return MessageErrorf(ErrInvalid, "Invalid option_type %s", oType)
	}

	return nil
}

type createInput struct {
	Title             string            `json:"title"`
	ContentObjectID   string            `json:"content_object_id"`
	MeetingID         int               `json:"meeting_id"`
	Method            string            `json:"method"`
	MethodConfig      json.RawMessage   `json:"method_config"`
	OptionType        string            `json:"option_type"`
	Options           []json.RawMessage `json:"options"`
	Visibility        string            `json:"visibility"`
	EntitledGroupIDs  []int             `json:"entitled_group_ids"`
	LiveVotingEnabled bool              `json:"live_voting_enabled"`
	Result            json.RawMessage   `json:"result"`
	AllowVoteSplit    bool              `json:"allow_vote_split"`
}

func parseCreateInput(r io.Reader, electronicVotingEnabled bool) (createInput, error) {
	var ci createInput
	if err := json.NewDecoder(r).Decode(&ci); err != nil {
		return createInput{}, MessageError(ErrInvalid, "Request body is not a valid json object.")
	}

	if ci.Title == "" {
		return createInput{}, MessageError(ErrInvalid, "Field 'title' can not be empty")
	}

	if ci.ContentObjectID == "" {
		return createInput{}, MessageError(ErrInvalid, "Field 'content_object_id' can not be empty")
	}

	if ci.MeetingID == 0 {
		return createInput{}, MessageError(ErrInvalid, "Field 'meeting_id' can not be empty")
	}

	if ci.Method == "" {
		return createInput{}, MessageError(ErrInvalid, "Field 'method' can not be empty")
	}

	requireOptions, err := method.RequireOptions(ci.Method)
	if err != nil {
		return createInput{}, fmt.Errorf("getting method: %w", err)
	}

	if requireOptions && len(ci.Options) == 0 {
		return createInput{}, MessageErrorf(ErrInvalid, "Method %s needs at least one option", ci.Method)
	}

	if ci.MethodConfig == nil {
		return createInput{}, MessageError(ErrInvalid, "Field 'method_config' can not be empty")
	}

	if ci.OptionType == "" && len(ci.Options) != 0 {
		return createInput{}, MessageError(ErrInvalid, "Field `option_type` has to be set, if options are given")
	}

	if ci.Visibility == "" {
		return createInput{}, MessageError(ErrInvalid, "Field 'visibility' can not be empty")
	}

	if ci.Visibility == "secret" && ci.AllowVoteSplit {
		return createInput{}, MessageError(ErrInvalid, "Vote splitting is not allowed for secret polls")
	}

	switch ci.Visibility {
	case "manually":
		if len(ci.EntitledGroupIDs) > 0 {
			return createInput{}, MessageError(ErrInvalid, "Entitled Group IDs can not be set when visibility is set to manually")
		}

	default:
		if !electronicVotingEnabled {
			return createInput{}, MessageError(ErrNotAllowed, "Electronic voting is not enabled. Only polls with visibility set to manually are allowed.")
		}

		if ci.Result != nil {
			return createInput{}, MessageError(ErrInvalid, "Result can only be set when visibility is set to manually")
		}
	}

	return ci, nil
}

// Update changes a poll.
func (v *Vote) Update(ctx context.Context, pollID int, requestUserID int, r io.Reader) error {
	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, poll.MeetingID, poll.ContentObjectID, requestUserID); err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	electronicVotingEnabled, err := dsfetch.New(v.flow).Organization_EnableElectronicVoting(1).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetch organization/1/enable_electronic_voting: %w", err)
	}

	ui, err := parseUpdateInput(r, poll, electronicVotingEnabled)
	if err != nil {
		return fmt.Errorf("parse update body: %w", err)
	}

	tx, err := v.querier.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var title *string
	if ui.Title != "" {
		title = &ui.Title
	}

	var visibility *string
	if ui.Visibility != "" {
		visibility = &ui.Visibility
	}

	var liveVotingEnabled *bool
	if v, ok := ui.LiveVotingEnabled.Value(); ok {
		liveVotingEnabled = &v
	}

	var result *string
	if ui.Result != nil {
		v := string(ui.Result)
		result = &v
	}

	var allowVoteSplit *bool
	if v, ok := ui.AllowVoteSplit.Value(); ok {
		allowVoteSplit = &v
	}

	sql := `
	UPDATE poll_t
	SET
		title = COALESCE($2, title),
		visibility = COALESCE($3, visibility),
		live_voting_enabled = COALESCE($4, live_voting_enabled),
		result = COALESCE($5, result),
		allow_vote_split = COALESCE($6, allow_vote_split)
	WHERE id = $1;`
	res, err := tx.Exec(ctx, sql, pollID, title, visibility, liveVotingEnabled, result, allowVoteSplit)
	if err != nil {
		return fmt.Errorf("update poll: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("poll %d not found", pollID)
	}

	if ui.Method != "" || ui.MethodConfig != nil {
		oldMethod, _, err := method.SplitConfigID(poll.ConfigID)
		if err != nil {
			return fmt.Errorf("getting poll method for poll %d: %w", poll.ID, err)
		}

		optionAmount := len(poll.OptionIDs)
		if ui.Options != nil {
			optionAmount = len(ui.Options)
		}

		if ui.Method == "" || ui.Method == oldMethod {
			if err := method.ConfigUpdate(ctx, v.flow, tx, poll.ConfigID, poll.State, optionAmount, ui.MethodConfig); err != nil {
				return fmt.Errorf("Update poll method for poll %d: %w", pollID, err)
			}
		} else {
			if err := method.ConfigDelete(ctx, tx, poll.ConfigID); err != nil {
				return fmt.Errorf("delete old config: %w", err)
			}

			newConfigID, err := method.ConfigCreate(ctx, tx, ui.Method, optionAmount, ui.MethodConfig)
			if err != nil {
				return fmt.Errorf("replace poll config: %w", err)
			}

			sql := `UPDATE poll_t SET config_id = $1 WHERE id = $2`
			if _, err := tx.Exec(ctx, sql, newConfigID, pollID); err != nil {
				return fmt.Errorf("update poll.config_id: %w", err)
			}
		}
	}

	if ui.OptionType != "" && len(ui.Options) > 0 {
		maxOptions, err := method.MaxOptionsAmount(ctx, v.flow, poll.ConfigID)
		if err != nil {
			return fmt.Errorf("getting max options amount: %w", err)
		}
		if maxOptions > len(ui.Options) {
			return MessageError(ErrInvalid, "Value of max_options_amount can not be higher then the amount of available options")
		}

		sql := "DELETE FROM poll_option_t WHERE poll_id = $1"
		if _, err := tx.Exec(ctx, sql, pollID); err != nil {
			return fmt.Errorf("deleting existing poll options: %w", err)
		}

		if err := saveOptions(ctx, tx, pollID, ui.OptionType, ui.Options); err != nil {
			return fmt.Errorf("save options: %w", err)
		}
	}

	if len(ui.EntitledGroupIDs) > 0 {
		deleteSQL := "DELETE FROM nm_group_poll_ids_poll_t WHERE poll_id = $1"
		if _, err := tx.Exec(ctx, deleteSQL, pollID); err != nil {
			return fmt.Errorf("deleting existing group associations: %w", err)
		}

		groupSQL := `
        INSERT INTO nm_group_poll_ids_poll_t (group_id, poll_id)
        SELECT unnest($1::int[]), $2`

		if _, err := tx.Exec(ctx, groupSQL, ui.EntitledGroupIDs, poll.ID); err != nil {
			return fmt.Errorf("insert group-poll relations: %w", err)
		}
	}

	if err := history.OneEntry(ctx, tx, requestUserID, poll.ContentObjectID, poll.MeetingID, "poll updated"); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

type updateInput struct {
	Title             string              `json:"title"`
	Method            string              `json:"method"`
	MethodConfig      json.RawMessage     `json:"method_config"`
	OptionType        string              `json:"option_type"`
	Options           []json.RawMessage   `json:"options"`
	Visibility        string              `json:"visibility"`
	EntitledGroupIDs  []int               `json:"entitled_group_ids"`
	LiveVotingEnabled dsfetch.Maybe[bool] `json:"live_voting_enabled"`
	Result            json.RawMessage     `json:"result"`
	AllowVoteSplit    dsfetch.Maybe[bool] `json:"allow_vote_split"`
}

func parseUpdateInput(r io.Reader, poll dsmodels.Poll, electronicVotingEnabled bool) (updateInput, error) {
	var ui updateInput
	if err := json.NewDecoder(r).Decode(&ui); err != nil {
		return updateInput{}, MessageError(ErrInvalid, "Request body is not a valid json object.")
	}

	if poll.Visibility == "manually" {
		if len(ui.EntitledGroupIDs) > 0 {
			return updateInput{}, MessageError(ErrNotAllowed, "Entitled Group IDs can not be set when visibility is set to manually")
		}
		return ui, nil
	}

	if ui.Visibility == "manually" {
		return updateInput{}, MessageError(ErrNotAllowed, "Poll.visibility can not be changed to manually")
	}

	if poll.State != "created" {
		if ui.OptionType != "" {
			return updateInput{}, MessageError(ErrNotAllowed, "Option type can only be changed before the poll has started")
		}

		if len(ui.Options) != 0 {
			return updateInput{}, MessageErrorf(ErrInvalid, "Options can only be changed before the poll has started")
		}

		if ui.Visibility != "" {
			return updateInput{}, MessageError(ErrNotAllowed, "Visibility can only be changed before the poll has started")
		}

		if ui.EntitledGroupIDs != nil {
			return updateInput{}, MessageError(ErrNotAllowed, "Entitled group ids can only be changed before the poll has started")
		}

		if !ui.AllowVoteSplit.Null() {
			return updateInput{}, MessageError(ErrNotAllowed, "Allow vote split can only be changed before the poll has started")
		}
	}

	if !electronicVotingEnabled {
		return updateInput{}, MessageError(ErrNotAllowed, "Electronic voting is not enabled. Only polls with visibility set to manually are allowed.")
	}

	if ui.Result != nil {
		return updateInput{}, MessageError(ErrNotAllowed, "Result can only be set when visibility is set to manually")
	}

	return ui, nil
}

// Delete removes a poll.
func (v *Vote) Delete(ctx context.Context, pollID int, requestUserID int) error {
	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, poll.MeetingID, poll.ContentObjectID, requestUserID); err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	tx, err := v.querier.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := method.ConfigDelete(ctx, tx, poll.ConfigID); err != nil {
		return fmt.Errorf("delete method: %w", err)
	}

	// TODO: This should be done in the schma with on_delete: CASCASE
	// See https://github.com/OpenSlides/openslides-meta/issues/220
	batch := &pgx.Batch{}
	batch.Queue(`DELETE FROM poll_option_t WHERE poll_id = $1`, pollID)
	batch.Queue(`DELETE FROM poll_ballot_t WHERE poll_id = $1`, pollID)
	batch.Queue(`DELETE FROM poll_ballot_user_t WHERE poll_id = $1`, pollID)
	batch.Queue(`DELETE FROM projection_t WHERE content_object_id_poll_id = $1`, pollID)
	batch.Queue(`DELETE FROM poll_entitled_user_t WHERE poll_id = $1`, pollID)
	batch.Queue(`DELETE FROM poll_t WHERE id = $1`, pollID)

	results := tx.SendBatch(ctx, batch)
	if err := results.Close(); err != nil {
		return fmt.Errorf("deleting poll related enties: %w", err)
	}

	if err := history.OneEntry(ctx, tx, requestUserID, poll.ContentObjectID, poll.MeetingID, "poll deleted"); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Start validates a poll and set its state to started.
func (v *Vote) Start(ctx context.Context, pollID int, requestUserID int) error {
	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, poll.MeetingID, poll.ContentObjectID, requestUserID); err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	if poll.State == "finished" {
		return MessageErrorf(ErrInvalid, "Poll %d is already finished", pollID)
	}

	if err := Preload(ctx, dsfetch.New(v.flow), poll.ID, poll.MeetingID); err != nil {
		return fmt.Errorf("preloading poll: %w", err)
	}

	tx, err := v.querier.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Set published, if live voting is enabled.
	sql := `UPDATE poll_t SET state = 'started', published = $2 WHERE id = $1 AND state != 'finished';`
	commandTag, err := tx.Exec(ctx, sql, pollID, poll.LiveVotingEnabled)
	if err != nil {
		return fmt.Errorf("set poll %d to started: %w", pollID, err)
	}

	if commandTag.RowsAffected() != 1 {
		return fmt.Errorf("poll %d not found or already in 'finished' state", pollID)
	}

	if err := history.OneEntry(ctx, tx, requestUserID, poll.ContentObjectID, poll.MeetingID, "poll started"); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Finalize ends a poll.
//
// - If in the started state, it creates poll/result.
// - Sets the state to `finished`.
// - Sets the `published` flag.
// - With the flag `anonymize`, clears the connection between poll_ballot and poll_ballot_user
func (v *Vote) Finalize(ctx context.Context, pollID int, requestUserID int, publish bool, anonymize bool) error {
	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, poll.MeetingID, poll.ContentObjectID, requestUserID); err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	if poll.State == "created" {
		return MessageErrorf(ErrInvalid, "Poll %d has not started yet.", pollID)
	}

	// Start the transaction as repeatable read so all reads happen on the same snapshot of the db.
	tx, err := v.querier.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Set a lock on first query. Postgres creates the repeatable read snapshot
	// on the first query. So the lock and the snapshot are created at the same
	// time.
	sql := `SELECT id FROM poll_t WHERE id = $1 FOR NO KEY UPDATE`
	if _, err := tx.Exec(ctx, sql, pollID); err != nil {
		return fmt.Errorf("select poll %d: %w", pollID, err)
	}

	historyMessages := make([]string, 0, 4)
	historyMessages = append(historyMessages, "poll finalized")

	if poll.State == `started` {
		if err := v.pollStop(ctx, tx, poll); err != nil {
			return fmt.Errorf("stop poll: %w", err)
		}
		historyMessages = append(historyMessages, "stopped")
	}

	if publish && !poll.Published {
		if err := v.pollPublish(ctx, tx, poll); err != nil {
			return fmt.Errorf("publish poll: %w", err)
		}
		historyMessages = append(historyMessages, "published")
	}

	if anonymize && !poll.Anonymized {
		if err := v.pollAnonymize(ctx, tx, poll); err != nil {
			return fmt.Errorf("anonymize poll: %w", err)
		}
		historyMessages = append(historyMessages, "anonymized")
	}

	if err := history.OneEntry(ctx, tx, requestUserID, poll.ContentObjectID, poll.MeetingID, historyMessages...); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func fetchBallots(ctx context.Context, tx pgx.Tx, pollID int) ([]method.Ballot, error) {
	raws, err := tx.Query(ctx, "SELECT weight, split, value FROM poll_ballot_t WHERE poll_id = $1", pollID)
	if err != nil {
		return nil, fmt.Errorf("select ballots: %w", err)
	}
	defer raws.Close()

	var ballots []method.Ballot
	for raws.Next() {
		var ballot method.Ballot
		if err := raws.Scan(&ballot.Weight, &ballot.Split, &ballot.Value); err != nil {
			return nil, fmt.Errorf("scan ballot: %w", err)
		}
		ballots = append(ballots, ballot)
	}

	if err := raws.Err(); err != nil {
		return nil, fmt.Errorf("raws error: %w", err)
	}

	return ballots, nil
}

func (v *Vote) pollStop(ctx context.Context, tx pgx.Tx, poll dsmodels.Poll) error {
	var state string
	if err := tx.QueryRow(ctx, "SELECT state FROM poll_t WHERE id = $1", poll.ID).Scan(&state); err != nil {
		return fmt.Errorf("get anonymized status: %w", err)
	}
	if state != "started" {
		// Only stop started polls. This check is necessary, since pg_notify can be laggy.
		return nil
	}

	ballots, err := fetchBallots(ctx, tx, poll.ID)
	if err != nil {
		return fmt.Errorf("fetch ballots of poll %d: %w", poll.ID, err)
	}

	if err := generateEntitledUsers(ctx, tx, poll.ID); err != nil {
		return fmt.Errorf("generate entitled meeting users: %w", err)
	}

	if poll.Visibility == "secret" {
		for i := range ballots {
			decrypted, err := decryptBallot(ballots[i].Value, v.gcmForSecretPolls)
			if err != nil {
				return fmt.Errorf("decrypting ballot: %w", err)
			}
			ballots[i].Value = decrypted
		}

		if err := rewriteBallots(ctx, tx, poll.ID, ballots); err != nil {
			return fmt.Errorf("rewrite ballots: %w", err)
		}
	}

	pm, err := v.resolveMethod(ctx, poll)
	if err != nil {
		return fmt.Errorf("resolve poll method: %w", err)
	}

	result, err := CreateResult(pm, poll.AllowVoteSplit, ballots)
	if err != nil {
		return fmt.Errorf("create poll result: %w", err)
	}

	sql := `UPDATE poll_t SET result = $1, state = 'finished' WHERE id = $2;`
	if _, err := tx.Exec(ctx, sql, result, poll.ID); err != nil {
		return fmt.Errorf("set result of poll %d: %w", poll.ID, err)
	}

	return nil
}

func (v *Vote) pollPublish(ctx context.Context, tx pgx.Tx, poll dsmodels.Poll) error {
	sql := `UPDATE poll_t SET published = TRUE WHERE id = $1;`
	if _, err := tx.Exec(ctx, sql, poll.ID); err != nil {
		return fmt.Errorf("set poll %d to published: %w", poll.ID, err)
	}
	return nil
}

func (v *Vote) pollAnonymize(ctx context.Context, tx pgx.Tx, poll dsmodels.Poll) error {
	if poll.Visibility == "named" {
		return MessageError(ErrNotAllowed, "A named-poll can not be anonymized.")
	}

	if err := rewriteBallotsPostgres(ctx, tx, poll.ID); err != nil {
		return fmt.Errorf("rewrite ballots: %w", err)
	}
	return nil
}

// rewriteBallots rewrites all ballots in a different order to the database, so
// all references to the original ballots are removed.
//
// Its sorts the ballots by its encrypted value. This is deterministic, so
// the same order will be used every time.
func rewriteBallots(ctx context.Context, tx pgx.Tx, pollID int, ballots []method.Ballot) error {
	var anonymized bool
	if err := tx.QueryRow(ctx, "SELECT anonymized FROM poll_t WHERE id = $1", pollID).Scan(&anonymized); err != nil {
		return fmt.Errorf("get anonymized status: %w", err)
	}
	if anonymized {
		// Do not anonymize a poll twice. This can happen, when a secret poll
		// gets finalized with the anonymize flag.
		return nil
	}

	sort.Slice(ballots, func(i, j int) bool {
		return ballots[i].Value < ballots[j].Value
	})

	if _, err := tx.Exec(ctx, "DELETE FROM poll_ballot_t WHERE poll_id = $1", pollID); err != nil {
		return fmt.Errorf("deleting old ballots: %w", err)
	}

	if _, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"poll_ballot_t"},
		[]string{"weight", "split", "value", "poll_id"},
		pgx.CopyFromSlice(len(ballots), func(i int) ([]any, error) {
			return []any{
				ballots[i].Weight,
				ballots[i].Split,
				ballots[i].Value,
				pollID,
			}, nil
		}),
	); err != nil {
		return fmt.Errorf("bulk inserting anonymized ballots: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE poll_t SET anonymized = TRUE WHERE id = $1`, pollID); err != nil {
		return fmt.Errorf("set anonymize on poll: %w", err)
	}

	return nil
}

// rewriteBallotsPostgres is simular then rewirteBallots, but does the rewrite
// in postgres.
func rewriteBallotsPostgres(ctx context.Context, tx pgx.Tx, pollID int) error {
	var anonymized bool
	if err := tx.QueryRow(ctx, "SELECT anonymized FROM poll_t WHERE id = $1", pollID).Scan(&anonymized); err != nil {
		return fmt.Errorf("get anonymized status: %w", err)
	}
	if anonymized {
		// Do not anonymize a poll twice. This can happen, when a secret poll
		// gets finalized with the anonymize flag.
		return nil
	}

	query := `
		WITH deleted_ballots AS (
			DELETE FROM poll_ballot_t
			WHERE poll_id = $1
			RETURNING weight, split, value, poll_id
		)
		INSERT INTO poll_ballot_t (weight, split, value, poll_id)
		SELECT weight, split, value, poll_id
		FROM deleted_ballots
		ORDER BY value ASC;`

	if _, err := tx.Exec(ctx, query, pollID); err != nil {
		return fmt.Errorf("rewrite and anonymize ballots: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE poll_t SET anonymized = TRUE WHERE id = $1`, pollID); err != nil {
		return fmt.Errorf("set anonymize on poll: %w", err)
	}

	return nil
}

// generateEntitledUsers fills in the field poll/entitled_meeting_user_ids
//
// It uses a set from all represented users, that have voted and all users in
// one of the entitled_group, that are currently allowed to vote.
func generateEntitledUsers(ctx context.Context, tx pgx.Tx, pollID int) error {
	var meetingConfig struct {
		delegationActivated  bool
		forbidDelegateToVote bool
	}

	configSQL := `
		SELECT
			COALESCE(m.users_enable_vote_delegations, false),
	        COALESCE(m.users_forbid_delegator_to_vote, false)
		FROM meeting_t m
		JOIN poll_t p ON p.meeting_id = m.id
		WHERE p.id = $1`

	if err := tx.QueryRow(ctx, configSQL, pollID).Scan(&meetingConfig.delegationActivated, &meetingConfig.forbidDelegateToVote); err != nil {
		return fmt.Errorf("getting meeting config: %w", err)
	}

	baseInsertSQL := `
		INSERT INTO poll_entitled_user_t (meeting_user_id, poll_id)
		SELECT meeting_user_id, $1 FROM (
			SELECT represented_meeting_user_id AS meeting_user_id
			FROM poll_ballot_user_t
			WHERE poll_id = $1

			UNION
	`

	var conditionSQL string
	switch {
	case !meetingConfig.delegationActivated:
		// Only check users in an entitled group
		conditionSQL = `
			SELECT mu.id
			FROM meeting_user_t mu
			JOIN nm_group_meeting_user_ids_meeting_user_t gmu ON gmu.meeting_user_id = mu.id
			JOIN nm_group_poll_ids_poll_t gpol ON gpol.group_id = gmu.group_id
			JOIN nm_meeting_present_user_ids_user_t pu ON pu.meeting_id = mu.meeting_id AND pu.user_id = mu.user_id
			WHERE gpol.poll_id = $1
		`

	case meetingConfig.forbidDelegateToVote:
		// Only check delegation from users in group
		conditionSQL = `
			SELECT mu.id
			FROM meeting_user_t mu
			JOIN nm_group_meeting_user_ids_meeting_user_t gmu ON gmu.meeting_user_id = mu.id
			JOIN nm_group_poll_ids_poll_t gpol ON gpol.group_id = gmu.group_id
			JOIN nm_meeting_user_vote_delegated_to_ids_meeting_user_t del ON del.vote_delegations_from_id = mu.id
			JOIN meeting_user_t delegate_mu ON delegate_mu.id = del.vote_delegated_to_id
			JOIN nm_meeting_present_user_ids_user_t pu ON pu.meeting_id = delegate_mu.meeting_id AND pu.user_id = delegate_mu.user_id
			WHERE gpol.poll_id = $1
		`

	default:
		// Check users and there delegations
		conditionSQL = `
			SELECT mu.id
			FROM meeting_user_t mu
			JOIN nm_group_meeting_user_ids_meeting_user_t gmu ON gmu.meeting_user_id = mu.id
			JOIN nm_group_poll_ids_poll_t gpol ON gpol.group_id = gmu.group_id
			WHERE gpol.poll_id = $1
			  AND (
			      EXISTS (
			          SELECT 1 FROM nm_meeting_present_user_ids_user_t pu
			          WHERE pu.meeting_id = mu.meeting_id AND pu.user_id = mu.user_id
			      )
			      OR
			      EXISTS (
			          SELECT 1
			          FROM nm_meeting_user_vote_delegated_to_ids_meeting_user_t del
			          JOIN meeting_user_t delegate_mu ON delegate_mu.id = del.vote_delegated_to_id
			          JOIN nm_meeting_present_user_ids_user_t pu_del ON pu_del.meeting_id = delegate_mu.meeting_id AND pu_del.user_id = delegate_mu.user_id
			          WHERE del.vote_delegations_from_id = mu.id
			      )
			  )
		`
	}

	finalSQL := baseInsertSQL + conditionSQL + `
		) AS entitled_users
		ON CONFLICT DO NOTHING;
	`

	if _, err := tx.Exec(ctx, finalSQL, pollID); err != nil {
		return fmt.Errorf("inserting entitled users: %w", err)
	}

	return nil
}

// Reset removes all ballots from a poll and sets its state to created.
func (v *Vote) Reset(ctx context.Context, pollID int, requestUserID int) error {
	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	if err := canManagePoll(ctx, v.flow, poll.MeetingID, poll.ContentObjectID, requestUserID); err != nil {
		return fmt.Errorf("check permissions: %w", err)
	}

	tx, err := v.querier.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	deleteBallotQuery := `DELETE FROM poll_ballot_t WHERE poll_id = $1`
	if _, err := tx.Exec(ctx, deleteBallotQuery, pollID); err != nil {
		return fmt.Errorf("delete ballots: %w", err)
	}

	deleteBallotUserQuery := `DELETE FROM poll_ballot_user_t WHERE poll_id = $1`
	if _, err := tx.Exec(ctx, deleteBallotUserQuery, pollID); err != nil {
		return fmt.Errorf("delete ballots: %w", err)
	}

	state := "created"
	if poll.Visibility == "manually" {
		state = "finished"
	}

	// Reset state, published and result. published is always false on started, even on live_voting.
	updateQuery := `UPDATE poll_t SET state = $1, published = FALSE, result = '', anonymized = FALSE WHERE id = $2`
	if _, err := tx.Exec(ctx, updateQuery, state, pollID); err != nil {
		return fmt.Errorf("reset poll state: %w", err)
	}

	if err := history.OneEntry(ctx, tx, requestUserID, poll.ContentObjectID, poll.MeetingID, "poll reset"); err != nil {
		return fmt.Errorf("write history: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// Vote validates and saves the ballot of a user.
func (v *Vote) Vote(ctx context.Context, pollID, requestUserID int, r io.Reader) error {
	if requestUserID == 0 {
		return MessageErrorf(ErrInvalid, "Anonymous can not vote")
	}

	poll, err := fetchPoll(ctx, v.flow, pollID)
	if err != nil {
		return fmt.Errorf("fetching poll: %w", err)
	}

	var body struct {
		MeetingUserID dsfetch.Maybe[int] `json:"meeting_user_id"`
		Value         json.RawMessage    `json:"value"`
		Split         bool               `json:"split"`
	}

	if err := json.NewDecoder(r).Decode(&body); err != nil {
		return MessageError(ErrInvalid, "Invalid body")
	}

	if body.Split && !poll.AllowVoteSplit {
		return MessageErrorf(ErrInvalid, "Vote split is not allowed for poll %d", poll.ID)
	}

	fetch := dsfetch.New(v.flow)
	actingMeetingUserID, found, err := getMeetingUser(ctx, fetch, requestUserID, poll.MeetingID)
	if err != nil {
		return fmt.Errorf("getting meeting user of request user: %w", err)
	}
	if !found {
		return MessageErrorf(ErrInvalid, "You have to be in the meeting to vote")
	}

	representedMeetingUserID := actingMeetingUserID
	if meetingUserID, set := body.MeetingUserID.Value(); set {
		representedMeetingUserID = meetingUserID
	}

	if err := allowedToVote(ctx, fetch, poll, representedMeetingUserID, actingMeetingUserID); err != nil {
		return fmt.Errorf("allowedToVote: %w", err)
	}

	ballotValue := string(body.Value)
	if poll.Visibility == "secret" {
		ballotValue, err = v.encryptBallot(ballotValue)
		if err != nil {
			return fmt.Errorf("encrypting ballot value: %w", err)
		}
	}

	weight, err := CalcVoteWeight(ctx, fetch, representedMeetingUserID)
	if err != nil {
		return fmt.Errorf("calc vote weight: %w", err)
	}

	if !poll.AllowInvalid {
		splitted := map[decimal.Decimal]json.RawMessage{decimal.Zero: body.Value}

		if body.Split {
			splitted, err = split(weight, body.Value)
			if err != nil {
				return fmt.Errorf("split vote: %w", err)
			}
		}

		pm, err := v.resolveMethod(ctx, poll)
		if err != nil {
			return fmt.Errorf("resolve poll method: %w", err)
		}

		for _, value := range splitted {
			if err := pm.ValidateBallot(value); err != nil {
				return fmt.Errorf("validate ballot: %w", err)
			}
		}
	}

	query := `WITH
    poll_check AS (
        SELECT
            id,
            state,
            CASE
                WHEN state != 'started' THEN 'POLL_NOT_STARTED'
                ELSE 'POLL_VALID'
            END AS poll_status
        FROM poll_t
        WHERE id = $1
        FOR KEY SHARE
    ),
    inserted_ballot_user AS (
        INSERT INTO poll_ballot_user_t (poll_id, acting_meeting_user_id, represented_meeting_user_id)
        SELECT $1, $2, $3
        FROM poll_check
        WHERE poll_check.poll_status = 'POLL_VALID'
        RETURNING id
    ),
    inserted_ballot AS (
        INSERT INTO poll_ballot_t (poll_id, value, weight, poll_ballot_user_id)
        SELECT $1, $4, $5, id
        FROM inserted_ballot_user
        RETURNING id
    )
	SELECT
    CASE
        WHEN inserted_ballot.id IS NOT NULL THEN 'VALID'
        WHEN poll_check.poll_status IS NOT NULL THEN poll_check.poll_status
        ELSE 'POLL_NOT_EXISTS'
    END AS status
	FROM poll_check
	LEFT JOIN inserted_ballot ON true;`

	var result string
	err = v.querier.QueryRow(ctx, query, pollID, actingMeetingUserID, representedMeetingUserID, ballotValue, weight).Scan(&result)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == PgErrUniqueViolation {
				return MessageErrorf(ErrDoubleVote, "You can not vote again on poll %d", pollID)
			}

			if pgErr.Code == PgErrForeignKeyViolation {
				return MessageErrorf(ErrNotExists, "Poll %d does not exist", pollID)
			}
		}
		return fmt.Errorf("vote query: %w", err)
	}

	switch result {
	case "VALID":
		return nil
	case "POLL_NOT_STARTED":
		return MessageErrorf(ErrNotStarted, "Poll %d is not started", pollID)
	case "POLL_NOT_EXISTS":
		return MessageErrorf(ErrNotExists, "Poll %d does not exist", pollID)
	}
	return fmt.Errorf("unknown error: %v", result)
}

// encryptBallot encrypts the given value with AES using the key for secret polls.
func (v *Vote) encryptBallot(ballotValue string) (string, error) {
	nonce := make([]byte, v.gcmForSecretPolls.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("create nonce: %w", err)
	}

	encryptedValue := v.gcmForSecretPolls.Seal(nonce, nonce, []byte(ballotValue), nil)

	return base64.StdEncoding.EncodeToString(encryptedValue), nil
}

// decryptBallot decrypt the given value with AES using the key for secret polls.
func decryptBallot(encryptedBallot string, gcmForSecretPolls cipher.AEAD) (string, error) {
	encryptedValue, err := base64.StdEncoding.DecodeString(encryptedBallot)
	if err != nil {
		return "", fmt.Errorf("base64 decode encrypted ballot: %w", err)
	}

	nonceSize := gcmForSecretPolls.NonceSize()
	if len(encryptedValue) < nonceSize {
		return "", fmt.Errorf("encrypted ballot too short")
	}

	nonce, ciphertext := encryptedValue[:nonceSize], encryptedValue[nonceSize:]

	plaintext, err := gcmForSecretPolls.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

// resolveMethod returns the poll method for a poll.
func (v *Vote) resolveMethod(ctx context.Context, poll dsmodels.Poll) (method.Method, error) {
	method, err := method.ResolveMethod(ctx, v.flow, poll.ConfigID, poll.OptionIDs)
	if err != nil {
		return nil, fmt.Errorf("method.ResolveMethod: %w", err)
	}
	return method, nil
}

// split split sa vote and valides the weight
func split(maxWeight decimal.Decimal, value json.RawMessage) (map[decimal.Decimal]json.RawMessage, error) {
	var splitVotes map[decimal.Decimal]json.RawMessage
	if err := json.Unmarshal(value, &splitVotes); err != nil {
		return nil, errors.Join(MessageError(ErrInvalid, "Invalid split votes"), err)
	}

	var splitWeightSum decimal.Decimal
	for splitWeight := range splitVotes {
		splitWeightSum = splitWeightSum.Add(splitWeight)
	}

	if splitWeightSum.Cmp(maxWeight) == 1 {
		return nil, MessageError(ErrInvalid, "Split weight exceeds your vote weight.")
	}

	return splitVotes, nil
}

// allowedToVote checks, that the represented user can vote and the acting user
// can vote for him.
func allowedToVote(
	ctx context.Context,
	ds *dsfetch.Fetch,
	poll dsmodels.Poll,
	representedMeetingUserID int,
	actingMeetingUserID int,
) error {
	if representedMeetingUserID == 0 {
		return MessageError(ErrNotAllowed, "You can not vote for anonymous.")
	}

	if err := ensurePresent(ctx, ds, actingMeetingUserID); err != nil {
		return fmt.Errorf("ensure acting user %d is present: %w", actingMeetingUserID, err)
	}

	groupIDs, err := ds.MeetingUser_GroupIDs(representedMeetingUserID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching groups of meeting_user %d: %w", representedMeetingUserID, err)
	}

	if !hasCommon(groupIDs, poll.EntitledGroupIDs) {
		return MessageErrorf(ErrNotAllowed, "Meeting User %d is not allowed to vote. He is not in an entitled group", representedMeetingUserID)
	}

	delegationActivated, err := ds.Meeting_UsersEnableVoteDelegations(poll.MeetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching meeting/user_enable_vote_delegations: %w", err)
	}

	forbitDelegateToVote, err := ds.Meeting_UsersForbidDelegatorToVote(poll.MeetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching meeting/users_forbid_delegator_to_vote: %w", err)
	}

	delegationList, err := ds.MeetingUser_VoteDelegatedToIDs(representedMeetingUserID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching meeting_user/vote_delegated_to_ids: %w", err)
	}

	if delegationActivated && forbitDelegateToVote && len(delegationList) > 0 && representedMeetingUserID == actingMeetingUserID {
		return MessageError(ErrNotAllowed, "You have delegated your vote and therefore can not vote for your self")
	}

	if representedMeetingUserID == actingMeetingUserID {
		return nil
	}

	if !delegationActivated {
		return MessageErrorf(ErrNotAllowed, "Vote delegation is not activated in meeting %d", poll.MeetingID)
	}

	if !slices.Contains(delegationList, actingMeetingUserID) {
		return MessageErrorf(ErrNotAllowed, "You can not vote for meeting user %d", representedMeetingUserID)
	}

	return nil
}

// CalcVoteWeight calculates the vote weight for a user in a meeting.
//
// voteweight is a DecimalField with 6 zeros.
func CalcVoteWeight(ctx context.Context, fetch *dsfetch.Fetch, meetingUserID int) (decimal.Decimal, error) {
	defaultVoteWeight, _ := decimal.NewFromString("1.000000")
	userID, err := fetch.MeetingUser_UserID(meetingUserID).Value(ctx)
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("getting user ID from meeting user: %w", err)
	}

	meetingID, err := fetch.MeetingUser_MeetingID(meetingUserID).Value(ctx)
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("getting meeting ID from meeting user: %w", err)
	}

	var voteWeightEnabled bool
	var meetingUserVoteWeight decimal.Decimal
	var userDefaultVoteWeight decimal.Decimal
	fetch.Meeting_UsersEnableVoteWeight(meetingID).Lazy(&voteWeightEnabled)
	fetch.MeetingUser_VoteWeight(meetingUserID).Lazy(&meetingUserVoteWeight)
	fetch.User_DefaultVoteWeight(userID).Lazy(&userDefaultVoteWeight)

	if err := fetch.Execute(ctx); err != nil {
		return decimal.Decimal{}, fmt.Errorf("getting vote weight values from db: %w", err)
	}

	if !voteWeightEnabled {
		return defaultVoteWeight, nil
	}

	if !meetingUserVoteWeight.IsZero() {
		return meetingUserVoteWeight, nil
	}

	if !userDefaultVoteWeight.IsZero() {
		return userDefaultVoteWeight, nil
	}

	return defaultVoteWeight, nil
}

// CreateResult creates the result from a list of votes.
func CreateResult(method method.Method, allowVoteSplit bool, ballots []method.Ballot) (string, error) {
	if allowVoteSplit {
		ballots = splitVote(method, ballots)
	}

	return method.Result(ballots)
}

func splitVote(m method.Method, ballots []method.Ballot) []method.Ballot {
	var splittedBallots []method.Ballot
	for _, ballot := range ballots {
		if !ballot.Split {
			splittedBallots = append(splittedBallots, ballot)
			continue
		}

		splitted, err := split(ballot.Weight, json.RawMessage(ballot.Value))
		if err != nil {
			// If the ballot value can not be splitted, just use it as value.
			// It will probably be counted as invalid.
			splittedBallots = append(splittedBallots, ballot)
			continue
		}

		splittedBallots = append(splittedBallots, ballotsFromSplitted(m, ballot, splitted)...)
	}
	return splittedBallots
}

func ballotsFromSplitted(m method.Method, ballot method.Ballot, splitted map[decimal.Decimal]json.RawMessage) []method.Ballot {
	var fromThisBallot []method.Ballot
	for splitWeight, splitValue := range splitted {
		if err := m.ValidateBallot(splitValue); err != nil {
			return []method.Ballot{ballot}
		}

		fromThisBallot = append(fromThisBallot, method.Ballot{
			Weight: splitWeight,
			Value:  string(splitValue),
			Split:  true,
		})
	}
	return fromThisBallot
}

func fetchPoll(ctx context.Context, getter flow.Getter, pollID int) (dsmodels.Poll, error) {
	ds := dsmodels.New(getter)
	poll, err := ds.Poll(pollID).First(ctx)
	if err != nil {
		var doesNotExist dsfetch.DoesNotExistError
		if errors.As(err, &doesNotExist) {
			return dsmodels.Poll{}, MessageErrorf(ErrNotExists, "Poll %d does not exist", pollID)
		}
		return dsmodels.Poll{}, fmt.Errorf("loading poll %d: %w", pollID, err)
	}

	return poll, nil
}

func getMeetingUser(ctx context.Context, fetch *dsfetch.Fetch, userID, meetingID int) (int, bool, error) {
	meetingUserIDs, err := fetch.User_MeetingUserIDs(userID).Value(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("getting all meeting_user ids: %w", err)
	}

	meetingIDs := make([]int, len(meetingUserIDs))
	for i := range meetingUserIDs {
		fetch.MeetingUser_MeetingID(meetingUserIDs[i]).Lazy(&meetingIDs[i])
	}

	if err := fetch.Execute(ctx); err != nil {
		return 0, false, fmt.Errorf("get all meeting IDs: %w", err)
	}

	idx := slices.Index(meetingIDs, meetingID)
	if idx == -1 {
		return 0, false, nil
	}

	return meetingUserIDs[idx], true, nil
}

func canManagePoll(ctx context.Context, getter flow.Getter, meetingID int, contentObjectID string, userID int) error {
	collection, _, found := strings.Cut(contentObjectID, "/")
	if !found {
		return fmt.Errorf("invalid content object id: %s", contentObjectID)
	}

	var requiredPerm perm.TPermission
	switch collection {
	case "motion":
		requiredPerm = perm.MotionCanManagePolls
	case "assignment":
		requiredPerm = perm.AssignmentCanManagePolls
	case "topic":
		requiredPerm = perm.AgendaItemCanManagePolls
	default:
		return fmt.Errorf(
			"invalid content object id %s, only motion, assignment or topic allowed",
			contentObjectID,
		)
	}

	userPerms, err := perm.New(ctx, dsfetch.New(getter), userID, meetingID)
	if err != nil {
		return fmt.Errorf("calculate user permissions: %w", err)
	}

	if !userPerms.Has(requiredPerm) {
		return MessageError(ErrNotAllowed, "You are not allowed to manage a poll")
	}

	return nil
}

func ensurePresent(ctx context.Context, ds *dsfetch.Fetch, meetingUser int) error {
	meetingID, err := ds.MeetingUser_MeetingID(meetingUser).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching meeting ID: %w", err)
	}

	userID, err := ds.MeetingUser_UserID(meetingUser).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching user ID: %w", err)
	}

	presentMeetings, err := ds.User_IsPresentInMeetingIDs(userID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching is present in meetings: %w", err)
	}

	if !slices.Contains(presentMeetings, meetingID) {
		return MessageErrorf(ErrNotAllowed, "You have to be present in meeting %d", meetingID)
	}

	return nil
}

func hasCommon(list1, list2 []int) bool {
	return slices.ContainsFunc(list1, func(a int) bool {
		return slices.Contains(list2, a)
	})
}

// Preload loads all data in the cache, that is needed later for the vote
// requests.
func Preload(ctx context.Context, flow flow.Getter, pollID int, meetingID int) error {
	ds := dsmodels.New(flow)
	var dummyBool bool
	ds.Meeting_UsersEnableVoteWeight(meetingID).Lazy(&dummyBool)
	ds.Meeting_UsersEnableVoteDelegations(meetingID).Lazy(&dummyBool)
	ds.Meeting_UsersForbidDelegatorToVote(meetingID).Lazy(&dummyBool)

	q := ds.Poll(pollID)
	q = q.Preload(q.EntitledGroupList().MeetingUserList().User())
	q = q.Preload(q.EntitledGroupList().MeetingUserList().VoteDelegatedToList().User())
	poll, err := q.First(ctx)
	if err != nil {
		return fmt.Errorf("fetch preload data: %w", err)
	}

	configCollection, configIDStr, found := strings.Cut(poll.ConfigID, "/")
	if !found {
		return fmt.Errorf("invalid value in configID: %s", poll.ConfigID)
	}

	configID, err := strconv.Atoi(configIDStr)
	if err != nil {
		return fmt.Errorf("invalid value in configID. Second part has to be an int: %s", poll.ConfigID)
	}

	switch configCollection {
	case "poll_config_approval":
		_, err := ds.PollConfigApproval(configID).First(ctx)
		if err != nil {
			return fmt.Errorf("fetch poll config approval: %w", err)
		}

	case "poll_config_selection":
		_, err := ds.PollConfigSelection(configID).First(ctx)
		if err != nil {
			return fmt.Errorf("fetch poll config selection: %w", err)
		}

	case "poll_config_rating_score":
		_, err := ds.PollConfigRatingScore(configID).First(ctx)
		if err != nil {
			return fmt.Errorf("fetch poll config rating score: %w", err)
		}

	case "poll_config_rating_approval":
		_, err := ds.PollConfigRatingApproval(configID).First(ctx)
		if err != nil {
			return fmt.Errorf("fetch poll config rating approval: %w", err)
		}

	default:
		return fmt.Errorf("invalid config collection. Unknown method: %s", configCollection)

	}

	return nil
}

// DBQuerier is either a pgx-connection or a pgx-pool.
type DBQuerier interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

const (
	PgErrUniqueViolation     = "23505"
	PgErrForeignKeyViolation = "23503"
)
