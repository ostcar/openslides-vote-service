package postgres

import (
	"bytes"
	"context"
	_ "embed" // Needed for file embedding
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Backend holds the state of the backend.
//
// Has to be initializes with New().
type Backend struct {
	pool *pgxpool.Pool
}

// New creates a new connection pool.
func New(ctx context.Context, connString string) (*Backend, error) {
	conf, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("invalid connection url: %w", err)
	}

	// Fix issue with gbBouncer. The documentation says, that this make the
	// connection slower. We have to test the performance. Maybe it is better to
	// remove the connection pool here or not use bgBouncer at all.
	//
	// See https://github.com/OpenSlides/openslides-vote-service/pull/66
	conf.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(ctx, conf)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	b := Backend{
		pool: pool,
	}

	return &b, nil
}

func (b *Backend) String() string {
	return "postgres"
}

// Wait blocks until a connection to postgres can be established.
func (b *Backend) Wait(ctx context.Context) {
	for ctx.Err() == nil {
		err := b.pool.Ping(ctx)
		if err == nil {
			return
		}
		log.Info("Waiting for postgres: %v", err)
		time.Sleep(500 * time.Millisecond)
	}
}

// Migrate creates the database schema.
func (b *Backend) Migrate(ctx context.Context) error {
	if _, err := b.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("creating schema: %w", err)
	}
	return nil
}

// Close closes all connections. It blocks, until all connection are closed.
func (b *Backend) Close() {
	b.pool.Close()
}

// Start starts a poll.
func (b *Backend) Start(ctx context.Context, pollID int) error {
	sql := `
	INSERT INTO vote.poll (id, stopped) VALUES ($1, false) ON CONFLICT DO NOTHING;
	`
	log.Debug("SQL: `%s` (values: %d)", sql, pollID)
	if _, err := b.pool.Exec(ctx, sql, pollID); err != nil {
		return fmt.Errorf("insert poll: %w", err)
	}
	return nil
}

// Vote adds a vote to a poll.
//
// If an transaction error happens, the vote is saved again. This is done until
// either the vote is saved or the given context is canceled.
func (b *Backend) Vote(ctx context.Context, pollID int, userID int, object []byte) error {
	err := continueOnTransactionError(ctx, func() error {
		return b.voteOnce(ctx, pollID, userID, object)
	})

	return err
}

// voteOnce tries to add the vote once.
func (b *Backend) voteOnce(ctx context.Context, pollID int, userID int, object []byte) (err error) {
	log.Debug("SQL: Begin transaction for vote")
	defer func() {
		log.Debug("SQL: End transaction for vote with error: %v", err)
	}()

	err = pgx.BeginTxFunc(
		ctx,
		b.pool,
		pgx.TxOptions{
			IsoLevel: "REPEATABLE READ",
		},
		func(tx pgx.Tx) error {
			sql := `
			SELECT stopped, user_ids 
			FROM vote.poll
			WHERE id = $1;
			`
			var stopped bool
			var uIDsRaw []byte
			log.Debug("SQL: `%s` (values: %d)", sql, pollID)
			if err := tx.QueryRow(ctx, sql, pollID).Scan(&stopped, &uIDsRaw); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return doesNotExistError{fmt.Errorf("unknown poll")}
				}
				return fmt.Errorf("fetching poll data: %w", err)
			}

			if stopped {
				return stoppedError{fmt.Errorf("poll is stopped")}
			}

			uIDs, err := userIDListFromBytes(uIDsRaw)
			if err != nil {
				return fmt.Errorf("parsing user ids: %w", err)
			}

			if err := uIDs.add(int32(userID)); err != nil {
				return fmt.Errorf("adding userID to voted users: %w", err)
			}

			uIDsRaw, err = uIDs.toBytes()
			if err != nil {
				return fmt.Errorf("converting user ids to bytes: %w", err)
			}

			sql = "UPDATE vote.poll SET user_ids = $1 WHERE id = $2;"
			log.Debug("SQL: `%s` (values: [user_ids]), %d", sql, pollID)
			if _, err := tx.Exec(ctx, sql, uIDsRaw, pollID); err != nil {
				return fmt.Errorf("writing user ids: %w", err)
			}

			sql = "INSERT INTO vote.objects (poll_id, vote) VALUES ($1, $2);"
			log.Debug("SQL: `%s` (values: %d, [vote]", sql, pollID)
			if _, err := tx.Exec(ctx, sql, pollID, object); err != nil {
				return fmt.Errorf("writing vote: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return fmt.Errorf("running transaction: %w", err)
	}
	return nil
}

// Stop ends a poll and returns all vote objects and users who have voted.
//
// If an transaction error happens, the poll is stopped again. This is done
// until either the poll is stopped or the given context is canceled.
func (b *Backend) Stop(ctx context.Context, pollID int) ([][]byte, []int, error) {
	var objs [][]byte
	var userIDs []int
	err := continueOnTransactionError(ctx, func() error {
		o, uids, err := b.stopOnce(ctx, pollID)
		if err != nil {
			return err
		}
		objs = o
		userIDs = uids
		return nil
	})

	return objs, userIDs, err
}

// stopOnce ends a poll and returns all vote objects.
func (b *Backend) stopOnce(ctx context.Context, pollID int) (objects [][]byte, users []int, err error) {
	log.Debug("SQL: Begin transaction for vote")
	defer func() {
		log.Debug("SQL: End transaction for vote with error: %v", err)
	}()

	err = pgx.BeginTxFunc(
		ctx,
		b.pool,
		pgx.TxOptions{
			IsoLevel: "REPEATABLE READ",
		},
		func(tx pgx.Tx) error {
			sql := "SELECT EXISTS(SELECT 1 FROM vote.poll WHERE id = $1);"
			log.Debug("SQL: `%s` (values: %d", sql, pollID)

			var exists bool
			if err := tx.QueryRow(ctx, sql, pollID).Scan(&exists); err != nil {
				return fmt.Errorf("fetching poll exists: %w", err)
			}

			if !exists {
				return doesNotExistError{fmt.Errorf("Poll does not exist")}
			}

			sql = "UPDATE vote.poll SET stopped = true WHERE id = $1;"
			if _, err := tx.Exec(ctx, sql, pollID); err != nil {
				return fmt.Errorf("setting poll %d to stopped: %w", pollID, err)
			}

			sql = `
			SELECT Obj.vote
			FROM vote.poll Poll
			LEFT JOIN vote.objects Obj ON Obj.poll_id = Poll.id
			WHERE Poll.id = $1;
			`
			log.Debug("SQL: `%s` (values: %d", sql, pollID)
			rows, err := tx.Query(ctx, sql, pollID)
			if err != nil {
				return fmt.Errorf("fetching vote objects: %w", err)
			}

			for rows.Next() {
				var bs []byte
				err = rows.Scan(&bs)
				if err != nil {
					return fmt.Errorf("parsind row: %w", err)
				}
				if len(bs) == 0 {
					continue
				}
				objects = append(objects, bs)
			}

			if err := rows.Err(); err != nil {
				return fmt.Errorf("parsing query rows: %w", err)
			}

			sql = `
			SELECT user_ids
			FROM vote.poll
			WHERE poll.id = $1;
			`
			var rawUserIDs []byte
			if err := tx.QueryRow(ctx, sql, pollID).Scan(&rawUserIDs); err != nil {
				return fmt.Errorf("fetching poll data: %w", err)
			}

			uIDs, err := userIDListFromBytes(rawUserIDs)
			if err != nil {
				return fmt.Errorf("parsing user ids: %w", err)
			}

			for _, id := range uIDs {
				users = append(users, int(id))
			}

			return nil
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("running transaction: %w", err)
	}
	return objects, users, nil
}

// Clear removes all data about a poll from the database.
func (b *Backend) Clear(ctx context.Context, pollID int) error {
	sql := "DELETE FROM vote.poll WHERE id = $1"
	log.Debug("SQL: `%s` (values: %d)", sql, pollID)
	if _, err := b.pool.Exec(ctx, sql, pollID); err != nil {
		return fmt.Errorf("deleting data of poll %d: %w", pollID, err)
	}
	return nil
}

// ClearAll removes all vote related data from postgres.
//
// It does this by dropping vote vote-schema. If other services would write
// thinks in this schema or hava a relation to this schema, then this would also
// delete this tables.
//
// Since the schema is deleted and afterwards recreated this command can also be
// used, if the db-schema has changed. It is kind of a migration.
func (b *Backend) ClearAll(ctx context.Context) error {
	sql := "DROP SCHEMA IF EXISTS vote CASCADE"
	log.Debug("SQL: `%s`", sql)
	if _, err := b.pool.Exec(ctx, sql); err != nil {
		return fmt.Errorf("deleting vote schema: %w", err)
	}

	if err := b.Migrate(ctx); err != nil {
		return fmt.Errorf("recreate schema: %w", err)
	}
	return nil
}

// VotedPolls tells for a list of poll IDs if the given userID has already
// voted.
func (b *Backend) VotedPolls(ctx context.Context, pollIDs []int, userIDs []int) (map[int][]int, error) {
	log.Debug("SQL: Begin voted polls")

	sql := `
	SELECT id, user_ids
	FROM vote.poll
	WHERE id = ANY ($1);
	`

	rows, err := b.pool.Query(ctx, sql, pollIDs)
	if err != nil {
		return nil, fmt.Errorf("fetching user_ids from poll objects: %w", err)
	}

	out := make(map[int][]int, len(pollIDs))
	for rows.Next() {
		var pid int
		var rawUIDs []byte
		if err := rows.Scan(&pid, &rawUIDs); err != nil {
			return nil, fmt.Errorf("parsing row: %w", err)
		}

		uIDs, err := userIDListFromBytes(rawUIDs)
		if err != nil {
			return nil, fmt.Errorf("parsing user ids: %w", err)
		}

		for _, userID := range userIDs {
			if uIDs.contains(int32(userID)) {
				out[pid] = append(out[pid], userID)
			}
		}
	}

	// Add values for non existing polls
	for _, id := range pollIDs {
		if _, ok := out[id]; !ok {
			out[id] = nil
		}
	}
	return out, nil
}

// VoteCount returns the amout of votes for each vote in the backend.
func (b *Backend) VoteCount(ctx context.Context) (map[int]int, error) {
	sql := `select poll_id, count(poll_id) from vote.objects GROUP BY poll_id;`

	rows, err := b.pool.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("fetching vote count from poll objects: %w", err)
	}

	count := make(map[int]int)
	for rows.Next() {
		var pollID int
		var amount int
		if err := rows.Scan(&pollID, &amount); err != nil {
			return nil, fmt.Errorf("parsind row: %w", err)
		}
		count[pollID] = amount
	}

	return count, nil
}

// ContinueOnTransactionError runs the given many times until is does not return
// an transaction error. Also stopes, when the given context is canceled.
func continueOnTransactionError(ctx context.Context, f func() error) error {
	var err error
	for ctx.Err() == nil {
		err = f()
		if err == nil {
			break
		}

		var perr *pgconn.PgError
		if !errors.As(err, &perr) {
			break
		}

		// The error code is returned if another vote has manipulated the vote
		// users while this vote was saved.
		if perr.Code != "40001" {
			break
		}
	}
	return err
}

type userIDList []int32

func userIDListFromBytes(raw []byte) (userIDList, error) {
	ints := make([]int32, len(raw)/4)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ints); err != nil {
		return nil, fmt.Errorf("decoding user ids: %w", err)
	}
	return userIDList(ints), nil
}

func (u userIDList) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, u); err != nil {
		return nil, fmt.Errorf("encoding user id %v: %w", u, err)
	}

	return buf.Bytes(), nil
}

// add adds the userID to the userIDs
func (u *userIDList) add(userID int32) error {
	// idx is either the index of userID or the place where it should be
	// inserted.
	ints := []int32(*u)
	idx := sort.Search(len(ints), func(i int) bool { return ints[i] >= userID })
	if idx < len(ints) && ints[idx] == userID {
		return doupleVoteError{fmt.Errorf("User has already voted")}
	}

	// Insert the index at the correct order.
	ints = append(ints[:idx], append([]int32{userID}, ints[idx:]...)...)
	*u = ints
	return nil
}

// contains returns true if the userID is contains the list of userIDs.
func (u *userIDList) contains(userID int32) bool {
	ints := []int32(*u)
	idx := sort.Search(len(ints), func(i int) bool { return ints[i] >= userID })
	return idx < len(ints) && ints[idx] == userID
}

func (u *userIDList) len() int {
	return len([]int32(*u))
}

type doesNotExistError struct {
	error
}

func (doesNotExistError) DoesNotExist() {}

type doupleVoteError struct {
	error
}

func (doupleVoteError) DoupleVote() {}

type stoppedError struct {
	error
}

func (stoppedError) Stopped() {}
