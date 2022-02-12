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
	keyState          = "vote_state_%d"
	keyVote           = "vote_data_%d"
	keyCounter        = "vote_counter"
	keyCounterChanges = "vote_counter_changes"
)

// Backend is a vote-Backend.
//
// Is tries to save the votes as fast as possible. All necessary checkes are
// done inside a lua-script so everything is done in one atomic step. It is
// expected that there is no backup from the redis database. Everyone with
// access to the redis database can see the vote results and how each user has
// voted.
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
		luaScriptClearAll: redis.NewScript(2, luaClearAll),
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
// Returns the number of votes on success.
// Returns -1 if the poll is not started.
// Returns -2 if the poll was stopped.
// Returns -3 if the user has already voted.
const luaVoteScript = `
local state = redis.call("GET",KEYS[1])
if state == false then 
	return -1
end

if state == "2" then
	return -2
end

local saved = redis.call("HSETNX",KEYS[2],ARGV[1],ARGV[2])
if saved == 0 then
	return -3
end

return redis.call("HLEN",KEYS[2])`

// Vote saves a vote in redis.
//
// It also checks, that the user did not vote before and that the poll is open.
func (b *Backend) Vote(ctx context.Context, pollID int, userID int, object []byte) (int, error) {
	conn := b.pool.Get()
	defer conn.Close()

	vKey := fmt.Sprintf(keyVote, pollID)
	sKey := fmt.Sprintf(keyState, pollID)

	log.Debug("Redis: lua script vote: '%s' 2 %s %s [userID] [vote]", luaVoteScript, sKey, vKey)
	result, err := redis.Int(b.luaScriptVote.Do(conn, sKey, vKey, userID, object))
	if err != nil {
		return 0, fmt.Errorf("executing luaVoteScript: %w", err)
	}

	log.Debug("Redis: Returned %d", result)
	if result < 0 {
		switch result {
		case -1:
			return 0, doesNotExistError{fmt.Errorf("poll is not started")}
		case -2:
			return 0, stoppedError{fmt.Errorf("poll is stopped")}
		case -3:
			return 0, doupleVoteError{fmt.Errorf("user has voted")}
		default:
			return 0, fmt.Errorf("lua returned with %d", result)
		}
	}

	return result, nil
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

	if log.IsDebug() {
		log.Debug("Redis: Recieved %v", data)
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
// KEYS[1] == count key
// KEYS[2] == count change key
// ARGV[1] == state key pattern
// ARGV[2] == vote data pattern
const luaClearAll = `
for _, key in ipairs(redis.call("KEYS", ARGV[1])) do
	redis.call("DEL", key)
end

for _, key in ipairs(redis.call("KEYS", ARGV[2])) do
	redis.call("DEL", key)
end

redis.call("DEL", KEYS[1], KEYS[2])
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

	log.Debug("Redis: lua script clear all: '%s' 2 %s %s %s %s", luaClearAll, keyCounter, keyCounterChanges, voteKeyPattern, stateKeyPattern)
	if _, err := b.luaScriptClearAll.Do(conn, keyCounter, keyCounterChanges, voteKeyPattern, stateKeyPattern); err != nil {
		return fmt.Errorf("removing keys: %w", err)
	}

	return nil
}

// VotedPolls tells for a list of poll IDs if the given userID has already
// voted.
//
// This command is not atomic.
func (b *Backend) VotedPolls(ctx context.Context, pollIDs []int, userID int) (map[int]bool, error) {
	conn := b.pool.Get()
	defer conn.Close()

	out := make(map[int]bool)
	for _, pollID := range pollIDs {
		key := fmt.Sprintf(keyVote, pollID)
		log.Debug("Redis: HEXISTS %s %d", key, userID)
		exist, err := redis.Bool(conn.Do("HEXISTS", key, userID))
		if err != nil {
			return nil, fmt.Errorf("hexists for key %s: %w", key, err)
		}
		out[pollID] = exist
	}
	return out, nil
}

// CountAdd adds one to the count for the poll.
func (b *Backend) CountAdd(ctx context.Context, pollID int) error {
	conn := b.pool.Get()
	defer conn.Close()

	// TODO: Atomic
	if _, err := conn.Do("HINCRBY", keyCounter, pollID, 1); err != nil {
		return fmt.Errorf("incrising counter: %w", err)
	}

	maxScore, err := b.maxID(conn)
	if err != nil {
		return fmt.Errorf("getting max score: %w", err)
	}

	if _, err := conn.Do("ZADD", keyCounterChanges, "GT", maxScore+1, pollID); err != nil {
		return fmt.Errorf("add poll id to changed keys: %w", err)
	}

	return nil
}

// CountClear deletes all counts for a poll.
func (b *Backend) CountClear(ctx context.Context, pollID int) error {
	conn := b.pool.Get()
	defer conn.Close()

	if _, err := conn.Do("HDEL", keyCounter, pollID); err != nil {
		return fmt.Errorf("delete counter: %w", err)
	}

	maxScore, err := b.maxID(conn)
	if err != nil {
		return fmt.Errorf("getting max score: %w", err)
	}

	if _, err := conn.Do("ZADD", keyCounterChanges, "GT", maxScore+1, pollID); err != nil {
		return fmt.Errorf("add poll id to changed keys: %w", err)
	}

	return nil
}

func (b *Backend) maxID(conn redis.Conn) (uint64, error) {
	rawMaxScore, err := redis.Uint64s(conn.Do("ZRANGE", keyCounterChanges, 0, 0, "REV", "WITHSCORES"))
	if err != nil {
		return 0, fmt.Errorf("calling zrange redis commant: %w", err)
	}

	var maxScore uint64
	if len(rawMaxScore) > 1 {
		maxScore = rawMaxScore[1]
	}
	return maxScore, nil
}

// Counters returns all counts of all polls since the given id.
//
// Returns a new ID that can be used the next time. Returns all counts for
// all polls if the id 0 is given.
//
// Blocks until there is new data.
func (b *Backend) Counters(ctx context.Context, id uint64, blocking bool) (newid uint64, counts map[int]int, err error) {
	// TODO Atomic
	conn := b.pool.Get()
	defer conn.Close()

	var pollIDs []int
	for ctx.Err() == nil {
		ids, err := b.counterRange(conn, id)
		if err != nil {
			return 0, nil, fmt.Errorf("getting changed poll ids: %w", err)
		}

		if len(ids) > 0 {
			pollIDs = ids
			break
		}

		if !blocking {
			return id, nil, nil
		}

		time.Sleep(time.Second)
	}

	if ctx.Err() != nil {
		return 0, nil, ctx.Err()
	}

	args := make([]interface{}, len(pollIDs)+1)
	args[0] = keyCounter

	for i, pid := range pollIDs {
		args[i+1] = pid
	}

	// TODO: Maybe use HGETALL when id == 0
	rawCounter, err := redis.Ints(conn.Do("HMGET", args...))
	if err != nil {
		return 0, nil, fmt.Errorf("calling `hmget %v`: %w", args, err)
	}

	counter := make(map[int]int, len(rawCounter))
	for i, v := range rawCounter {
		counter[pollIDs[i]] = v
	}

	maxScore, err := b.maxID(conn)
	if err != nil {
		return 0, nil, fmt.Errorf("getting max score: %w", err)
	}

	return maxScore, counter, nil
}

func (b *Backend) counterRange(conn redis.Conn, id uint64) ([]int, error) {
	rawValues, err := redis.Uint64s(conn.Do("ZRANGE", keyCounterChanges, fmt.Sprintf("(%d", id), "+inf", "BYSCORE", "WITHSCORES"))
	if err != nil {
		return nil, fmt.Errorf("getting changed keys: %w", err)
	}

	pollIDs := make([]int, len(rawValues)/2)

	for i, v := range rawValues {
		if i%2 != 0 {
			continue
		}
		pollIDs[i/2] = int(v)
	}

	return pollIDs, nil
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
