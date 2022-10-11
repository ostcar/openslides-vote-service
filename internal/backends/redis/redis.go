// Package redis implements a vote.Backend.
//
// Is tries to save the votes as fast as possible. All necessary checkes are
// done inside a lua-script so everything is done in one atomic step. It is
// expected that there is no backup from the redis database. Everyone with
// access to the redis database can see the vote results and how each user has
// voted.
//
// It uses the keys `vote_state_X` and `vote_data_X` where X is a pollID.
//
// The key `vote_state_X` has type int. It is a number that tells the current
// state of the poll. 1: Poll is started. 2: Poll is stopped.
//
// The key `vote_data_%X` has type hash. The key is a user id and the value the
// vote of the user.
package redis

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
	"github.com/gomodule/redigo/redis"
)

const (
	keyState = "vote_state_%d"
	keyVote  = "vote_data_%d"
)

// Backend is the vote-Backend.
//
// Has to be created with redis.New().
type Backend struct {
	pool *redis.Pool

	luaScriptVote     *redis.Script
	luaScriptClearAll *redis.Script
}

// New creates an initializes Redis instance.
func New(addr string) *Backend {
	pool := redis.Pool{
		MaxActive:   100,
		Wait:        true,
		MaxIdle:     10,
		IdleTimeout: 240 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}

	return &Backend{
		pool: &pool,

		luaScriptVote:     redis.NewScript(2, luaVoteScript),
		luaScriptClearAll: redis.NewScript(0, luaClearAll),
	}
}

// Wait blocks until a connection to redis can be established.
func (b *Backend) Wait(ctx context.Context) {
	for ctx.Err() == nil {
		conn := b.pool.Get()
		_, err := conn.Do("PING")
		conn.Close()
		if err == nil {
			return
		}
		log.Info("Waiting for redis: %v", err)
		time.Sleep(500 * time.Millisecond)
	}
}

func (b *Backend) String() string {
	return "redis"
}

// Start starts the poll.
func (b *Backend) Start(ctx context.Context, pollID int) error {
	conn := b.pool.Get()
	defer conn.Close()

	sKey := fmt.Sprintf(keyState, pollID)

	log.Debug("Redis: SETNX %s 1", sKey)
	if _, err := conn.Do("SETNX", sKey, 1); err != nil {
		return fmt.Errorf("set state key to 1: %w", err)
	}
	return nil
}

// luaVoteScript checks for condition and saves a vote if all checks pass.
//
// KEYS[1] == state key
// KEYS[2] == vote data
// ARGV[1] == userID
// ARGV[2] == Vote object
//
// Returns 0 on success
// Returns 1 if the poll is not started.
// Returns 2 if the poll was stopped.
// Returns 3 if the user has already voted.
const luaVoteScript = `
local state = redis.call("GET",KEYS[1])
if state == false then 
	return 1
end

if state == "2" then
	return 2
end

local saved = redis.call("HSETNX",KEYS[2],ARGV[1],ARGV[2])
if saved == 0 then
	return 3
end

return 0`

// Vote saves a vote in redis.
//
// It also checks, that the user did not vote before and that the poll is open.
func (b *Backend) Vote(ctx context.Context, pollID int, userID int, object []byte) error {
	conn := b.pool.Get()
	defer conn.Close()

	vKey := fmt.Sprintf(keyVote, pollID)
	sKey := fmt.Sprintf(keyState, pollID)

	log.Debug("Redis: lua script vote: '%s' 2 %s %s [userID] [vote]", luaVoteScript, sKey, vKey)
	result, err := redis.Int(b.luaScriptVote.Do(conn, sKey, vKey, userID, object))
	if err != nil {
		return fmt.Errorf("executing luaVoteScript: %w", err)
	}

	log.Debug("Redis: Returned %d", result)
	switch result {
	case 1:
		return doesNotExistError{fmt.Errorf("poll is not started")}
	case 2:
		return stoppedError{fmt.Errorf("poll is stopped")}
	case 3:
		return doupleVoteError{fmt.Errorf("user has voted")}
	default:
		return nil
	}
}

// Stop ends a poll.
//
// It returns all vote objects.
func (b *Backend) Stop(ctx context.Context, pollID int) ([][]byte, []int, error) {
	conn := b.pool.Get()
	defer conn.Close()

	vKey := fmt.Sprintf(keyVote, pollID)
	sKey := fmt.Sprintf(keyState, pollID)

	log.Debug("SET %s 2 XX", sKey)
	_, err := redis.String(conn.Do("SET", sKey, "2", "XX"))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil, doesNotExistError{fmt.Errorf("poll does not exist")}
		}
		return nil, nil, fmt.Errorf("set key %s to 2: %w", sKey, err)
	}

	log.Debug("REDIS: HVALS %s", vKey)
	data, err := redis.StringMap(conn.Do("HGETALL", vKey))
	if err != nil {
		return nil, nil, fmt.Errorf("getting vote objects from %s: %w", vKey, err)
	}

	userIDs := make([]int, 0, len(data))
	voteObjects := make([][]byte, 0, len(data))
	for uid, vote := range data {
		id, err := strconv.Atoi(uid)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid userID %s: %w", uid, err)
		}
		userIDs = append(userIDs, id)
		voteObjects = append(voteObjects, []byte(vote))
	}

	sort.Ints(userIDs)
	return voteObjects, userIDs, nil
}

// Clear delete all information from a poll.
func (b *Backend) Clear(ctx context.Context, pollID int) error {
	conn := b.pool.Get()
	defer conn.Close()

	vKey := fmt.Sprintf(keyVote, pollID)
	sKey := fmt.Sprintf(keyState, pollID)

	log.Debug("REDIS: DEL %s %s", vKey, sKey)
	if _, err := conn.Do("DEL", vKey, sKey); err != nil {
		return fmt.Errorf("removing keys: %w", err)
	}
	return nil
}

// luaClearAll removes all vote related data from redis.
//
// ARGV[1] == state key pattern
// ARGV[2] == vote data pattern
const luaClearAll = `
for _, key in ipairs(redis.call("KEYS", ARGV[1])) do
	redis.call("DEL", key)
end

for _, key in ipairs(redis.call("KEYS", ARGV[2])) do
	redis.call("DEL", key)
end
`

// ClearAll removes all data from all polls.
//
// It does this in an atomic way so it is save to call this function any time.
// But this functions makes use of the redis command KEYS, that has a O(N)
// performance. If there are a lot of polls in the database, this could take
// some time, stopping the hole redis instance.
//
// The redis documentations says:
//
// Warning: consider KEYS as a command that should only be used in production
// environments with extreme care. It may ruin performance when it is executed
// against large databases. This command is intended for debugging and special
// operations, such as changing your keyspace layout. Don't use KEYS in your
// regular application code.
//
// Don't use this function regulary.
func (b *Backend) ClearAll(ctx context.Context) error {
	conn := b.pool.Get()
	defer conn.Close()

	voteKeyPattern := strings.ReplaceAll(keyVote, "%d", "*")
	stateKeyPattern := strings.ReplaceAll(keyState, "%d", "*")

	log.Debug("Redis: lua script clear all: '%s' 2 %s %s", luaClearAll, voteKeyPattern, stateKeyPattern)
	if _, err := b.luaScriptClearAll.Do(conn, voteKeyPattern, stateKeyPattern); err != nil {
		return fmt.Errorf("removing keys: %w", err)
	}

	return nil
}

// VotedPolls tells for a list of poll IDs if the given userIDs have already
// voted.
//
// This command is not atomic.
func (b *Backend) VotedPolls(ctx context.Context, pollIDs []int, userIDs []int) (map[int][]int, error) {
	conn := b.pool.Get()
	defer conn.Close()

	out := make(map[int][]int)
	for _, pollID := range pollIDs {
		key := fmt.Sprintf(keyVote, pollID)

		args := make([]any, len(userIDs)+1)
		args[0] = key
		for i, uid := range userIDs {
			args[i+1] = uid
		}

		log.Debug("Redis: HMGET %v", args)
		votes, err := redis.Strings(conn.Do("HMGET", args...))
		if err != nil {
			return nil, fmt.Errorf("HMGET for key %s: %w", key, err)
		}

		out[pollID] = nil
		for i, userID := range userIDs {
			if votes[i] != "" {
				out[pollID] = append(out[pollID], userID)
			}
		}
	}
	return out, nil
}

// VoteCount returns the amout of votes for each vote in the backend.
func (b *Backend) VoteCount(ctx context.Context) (map[int]int, error) {
	conn := b.pool.Get()
	defer conn.Close()

	// TODO: This uses the redis `KEY` command, which should not be used on big
	// instances with lot of pools. Maybe create a new key that contains all id
	// of all started and stopped polls. This could also be used on clearAll. An
	// alternative is to introduce a key voteCount as a map from pollID to count
	// that get increased on successfull votes with HINCR.
	voteKeyPattern := strings.ReplaceAll(keyVote, "%d", "*")
	keys, err := redis.Strings(conn.Do("Keys", voteKeyPattern))
	if err != nil {
		return nil, fmt.Errorf("get all vote data keys: %w", err)
	}

	count := make(map[int]int, len(keys))
	for _, key := range keys {
		var pollID int
		found, err := fmt.Sscanf(key, keyVote, &pollID)
		if err != nil || found != 1 {
			return nil, fmt.Errorf("getting pollID: %d, %w", found, err)
		}

		amount, err := redis.Int(conn.Do("HLEN", key))
		if err != nil {
			return nil, fmt.Errorf("getting vote count for poll %d: %w", pollID, err)
		}
		count[pollID] = amount
	}

	return count, nil
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
