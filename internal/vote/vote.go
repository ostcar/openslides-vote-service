package vote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsfetch"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

// Decrypter decryptes the incomming votes.
type Decrypter interface {
	Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error)
	Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error)
	Clear(ctx context.Context, pollID string) error
}

// Vote holds the state of the service.
//
// Vote has to be initializes with vote.New().
type Vote struct {
	fastBackend Backend
	longBackend Backend
	ds          datastore.Getter
	decrypter   Decrypter
}

// New creates an initializes vote service.
func New(fast, long Backend, ds datastore.Getter, decrypter Decrypter) *Vote {
	return &Vote{
		fastBackend: fast,
		longBackend: long,
		ds:          ds,
		decrypter:   decrypter,
	}
}

func (v *Vote) backend(p pollConfig) Backend {
	backend := v.longBackend
	if p.backend == "fast" {
		backend = v.fastBackend
	}
	log.Debug("Used backend: %v", backend)
	return backend
}

func (v *Vote) qualifiedID(ctx context.Context, fetch *dsfetch.Fetch, id int) (string, error) {
	url, err := fetch.Organization_Url(1).Value(ctx)
	if err != nil {
		return "", fmt.Errorf("getting organization url: %v", err)
	}
	return fmt.Sprintf("%s/%d", url, id), nil
}

// Start an electronic vote.
//
// This function is idempotence. If you call it with the same input, you will
// get the same output. This means, that when a poll is stopped, Start() will
// not throw an error.
func (v *Vote) Start(ctx context.Context, pollID int) (pubkey []byte, pubKeySig []byte, err error) {
	log.Debug("Receive start event for poll %d", pollID)
	defer func() {
		log.Debug("End start event with error: %v", err)
	}()

	recorder := datastore.NewRecorder(v.ds)
	ds := dsfetch.New(recorder)

	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll: %w", err)
	}

	if poll.pollType == "analog" {
		return nil, nil, MessageError{ErrInvalid, "Analog poll can not be started"}
	}

	if err := poll.preload(ctx, ds); err != nil {
		return nil, nil, fmt.Errorf("preloading data: %w", err)
	}
	log.Debug("Preload cache. Received keys: %v", recorder.Keys())

	if poll.pollType == "crypt" {
		qid, err := v.qualifiedID(ctx, ds, pollID)
		if err != nil {
			return nil, nil, fmt.Errorf("building qualified id: %w", err)
		}

		pubkey, pubKeySig, err = v.decrypter.Start(ctx, qid)
		if err != nil {
			return nil, nil, fmt.Errorf("starting poll in decrypter: %w", err)
		}
	}

	backend := v.backend(poll)
	if err := backend.Start(ctx, pollID); err != nil {
		return nil, nil, fmt.Errorf("starting poll in the backend: %w", err)
	}

	return pubkey, pubKeySig, nil
}

// Stop ends a poll.
//
// This method is idempotence. Many requests with the same pollID will return
// the same data. Calling vote.Clear will stop this behavior.
func (v *Vote) Stop(ctx context.Context, pollID int) (json.RawMessage, []byte, []int, error) {
	log.Debug("Receive stop event for poll %d", pollID)

	ds := dsfetch.New(v.ds)
	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading poll: %w", err)
	}

	backend := v.backend(poll)
	ballots, userIDs, err := backend.Stop(ctx, pollID)
	if err != nil {
		var errNotExist interface{ DoesNotExist() }
		if errors.As(err, &errNotExist) {
			return nil, nil, nil, MessageError{ErrNotExists, fmt.Sprintf("Poll %d does not exist in the backend", pollID)}
		}

		return nil, nil, nil, fmt.Errorf("fetching vote objects: %w", err)
	}

	if poll.pollType != "crypt" {
		votes, err := ballotsToJSONList(ballots)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("encode ballots: %w", err)
		}

		return votes, nil, userIDs, nil
	}

	votes := make([][]byte, len(ballots))
	for i := range ballots {
		var vote struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(ballots[i], &vote); err != nil {
			return nil, nil, nil, fmt.Errorf("decoding vote from backend: %w", err)
		}

		votes[i] = vote.Value
	}

	qid, err := v.qualifiedID(ctx, ds, pollID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building qualified id: %w", err)
	}

	decrypted, signature, err := v.decrypter.Stop(ctx, qid, votes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypting votes: %w", err)
	}

	return decrypted, signature, userIDs, nil
}

func ballotsToJSONList(ballots [][]byte) (json.RawMessage, error) {
	encodable := make([]json.RawMessage, len(ballots))
	for i := range ballots {
		encodable[i] = ballots[i]
	}

	bs, err := json.Marshal(encodable)
	if err != nil {
		return nil, fmt.Errorf("encode votes to list: %w", err)
	}

	return bs, nil
}

// Clear removes all knowlage of a poll.
func (v *Vote) Clear(ctx context.Context, pollID int) (err error) {
	log.Debug("Receive clear event for poll %d", pollID)
	defer func() {
		log.Debug("End clear event with error: %v", err)
	}()

	if err := v.fastBackend.Clear(ctx, pollID); err != nil {
		return fmt.Errorf("clearing fastBackend: %w", err)
	}

	if err := v.longBackend.Clear(ctx, pollID); err != nil {
		return fmt.Errorf("clearing longBackend: %w", err)
	}

	ds := dsfetch.New(v.ds)
	qid, err := v.qualifiedID(ctx, ds, pollID)
	if err != nil {
		return fmt.Errorf("building qualified id: %w", err)
	}

	if err := v.decrypter.Clear(ctx, qid); err != nil {
		return fmt.Errorf("clearing decrypter: %w", err)
	}

	return nil
}

// ClearAll removes all knowlage of all polls and the datastore-cache.
func (v *Vote) ClearAll(ctx context.Context) (err error) {
	log.Debug("Receive clearAll event")
	defer func() {
		log.Debug("End clearAll event with error: %v", err)
	}()

	// Reset the cache if it has the ResetCach() method.
	type ResetCacher interface {
		ResetCache()
	}
	if r, ok := v.ds.(ResetCacher); ok {
		r.ResetCache()
	}

	if err := v.fastBackend.ClearAll(ctx); err != nil {
		return fmt.Errorf("clearing fastBackend: %w", err)
	}

	if err := v.longBackend.ClearAll(ctx); err != nil {
		return fmt.Errorf("clearing long Backend: %w", err)
	}

	// TODO: clear decrypter.

	return nil
}

// Vote validates and saves the vote.
func (v *Vote) Vote(ctx context.Context, pollID, requestUser int, r io.Reader) (err error) {
	log.Debug("Receive vote event for poll %d from user %d", pollID, requestUser)
	defer func() {
		log.Debug("End vote event with error: %v", err)
	}()

	ds := dsfetch.New(v.ds)
	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return fmt.Errorf("loading poll: %w", err)
	}
	log.Debug("Poll config: %v", poll)

	presentMeetings, err := ds.User_IsPresentInMeetingIDs(requestUser).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching is present in meetings: %w", err)
	}

	if !isPresent(poll.meetingID, presentMeetings) {
		return MessageError{ErrNotAllowed, fmt.Sprintf("You have to be present in meeting %d", poll.meetingID)}
	}

	var vote ballot
	if err := json.NewDecoder(r).Decode(&vote); err != nil {
		return MessageError{ErrInvalid, fmt.Sprintf("decoding payload: %v", err)}
	}

	voteUser, exist := vote.UserID.Value()
	if !exist {
		voteUser = requestUser
	}

	if voteUser == 0 {
		return MessageError{ErrNotAllowed, "Votes for anonymous user are not allowed"}
	}

	backend := v.backend(poll)

	if voteUser != requestUser {
		delegation, err := ds.User_VoteDelegatedToID(voteUser, poll.meetingID).Value(ctx)
		if err != nil {
			// If the user from the request body does not exist, then delegation
			// will be 0. This case is handled below.
			var errDoesNotExist dsfetch.DoesNotExistError
			if !errors.As(err, &errDoesNotExist) {
				return fmt.Errorf("fetching delegation from user %d in meeting %d: %w", voteUser, poll.meetingID, err)
			}
		}

		if delegation != requestUser {
			return MessageError{ErrNotAllowed, fmt.Sprintf("You can not vote for user %d", voteUser)}
		}
		log.Debug("Vote delegation")
	}

	groupIDs, err := ds.User_GroupIDs(voteUser, poll.meetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching groups of user %d in meeting %d: %w", voteUser, poll.meetingID, err)
	}

	if !equalElement(groupIDs, poll.groups) {
		return MessageError{ErrNotAllowed, fmt.Sprintf("User %d is not allowed to vote", voteUser)}
	}

	// voteData.Weight is a DecimalField with 6 zeros.
	// TODO: Disable vote weight on crypted votes
	var voteWeight string
	if ds.Meeting_UsersEnableVoteWeight(poll.meetingID).ErrorLater(ctx) {
		voteWeight = ds.User_VoteWeight(voteUser, poll.meetingID).ErrorLater(ctx)
		if voteWeight == "" {
			voteWeight = ds.User_DefaultVoteWeight(voteUser).ErrorLater(ctx)
		}
	}
	if err := ds.Err(); err != nil {
		return fmt.Errorf("getting vote weight: %w", err)
	}

	if voteWeight == "" {
		voteWeight = "1.000000"
	}

	log.Debug("Using voteWeight %s", voteWeight)

	voteData := struct {
		RequestUser int             `json:"request_user_id,omitempty"`
		VoteUser    int             `json:"vote_user_id,omitempty"`
		Value       json.RawMessage `json:"value"`
		Weight      string          `json:"weight"`
	}{
		requestUser,
		voteUser,
		vote.Value,
		voteWeight,
	}

	if poll.pollType != "named" {
		voteData.RequestUser = 0
		voteData.VoteUser = 0
	}

	bs, err := json.Marshal(voteData)
	if err != nil {
		return fmt.Errorf("decoding vote data: %w", err)
	}

	if err := backend.Vote(ctx, pollID, voteUser, bs); err != nil {
		var errNotExist interface{ DoesNotExist() }
		if errors.As(err, &errNotExist) {
			return ErrNotExists
		}

		var errDoupleVote interface{ DoupleVote() }
		if errors.As(err, &errDoupleVote) {
			return ErrDoubleVote
		}

		var errNotOpen interface{ Stopped() }
		if errors.As(err, &errNotOpen) {
			return ErrStopped
		}

		return fmt.Errorf("save vote: %w", err)
	}

	return nil
}

// VotedPolls tells, on which the requestUser has already voted.
func (v *Vote) VotedPolls(ctx context.Context, pollIDs []int, requestUser int, w io.Writer) (err error) {
	log.Debug("Receive voted event for polls %v from user %d", pollIDs, requestUser)
	defer func() {
		log.Debug("End voted event with error: %v", err)
	}()
	ds := dsfetch.New(v.ds)
	polls := make(map[int]bool)

	for _, backend := range []Backend{v.fastBackend, v.longBackend} {
		backendPolls, err := backend.VotedPolls(ctx, pollIDs, requestUser)
		if err != nil {
			return fmt.Errorf("getting polls from backend %s: %w", backend, err)
		}
		log.Debug("polls from backend %s: %v", backend, backendPolls)

		for pid, value := range backendPolls {
			poll, err := loadPoll(ctx, ds, pid)
			if err != nil {
				var errDoesNotExist dsfetch.DoesNotExistError
				if errors.As(err, &errDoesNotExist) {
					polls[pid] = false
					continue
				}
				return fmt.Errorf("loading poll: %w", err)
			}

			if v.backend(poll) == backend {
				polls[pid] = polls[pid] || value
			}
		}
	}
	log.Debug("Combined polls: %v", polls)

	if err := json.NewEncoder(w).Encode(polls); err != nil {
		return fmt.Errorf("encoding polls %v: %w", polls, err)
	}
	return nil
}

// VoteCount returns the vote_count for both backends combained
func (v *Vote) VoteCount(ctx context.Context) (map[int]int, error) {
	countFast, err := v.fastBackend.VoteCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("count from fast: %w", err)
	}

	countLong, err := v.longBackend.VoteCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("count from long: %w", err)
	}

	count := make(map[int]int, len(countFast)+len(countLong))
	for k, v := range countFast {
		count[k] = v
	}
	for k, v := range countLong {
		count[k] = v
	}
	return count, nil
}

// Backend is a storage for the poll options.
type Backend interface {
	// Start opens the poll for votes. To start a poll that is already started
	// is ok. To start an stopped poll is also ok, but it has to be a noop (the
	// stop-state does not change).
	Start(ctx context.Context, pollID int) error

	// Vote saves vote data into the backend. The backend has to check that the
	// poll is started and the userID has not voted before.
	//
	// If the user has already voted, an Error with method `DoupleVote()` has to
	// be returned. If the poll has not started, an error with the method
	// `DoesNotExist()` is required. An a stopped vote, it has to be `Stopped()`.
	//
	// The return value is the number of already voted objects.
	Vote(ctx context.Context, pollID int, userID int, object []byte) error

	// Stop ends a poll and returns all poll objects and all userIDs from users
	// that have voted. It is ok to call Stop() on a stopped poll. On a unknown
	// poll `DoesNotExist()` has to be returned.
	Stop(ctx context.Context, pollID int) ([][]byte, []int, error)

	// Clear has to remove all data. It can be called on a started or stopped or
	// non existing poll.
	Clear(ctx context.Context, pollID int) error

	// ClearAll removes all data from the backend.
	ClearAll(ctx context.Context) error

	// VotedPolls tells for a list of poll IDs if the given userID has already
	// voted.
	VotedPolls(ctx context.Context, pollIDs []int, userID int) (map[int]bool, error)

	// VoteCount returns the amout of votes for each vote in the backend.
	VoteCount(ctx context.Context) (map[int]int, error)

	fmt.Stringer
}

type pollConfig struct {
	id                int
	meetingID         int
	backend           string
	pollType          string
	method            string
	groups            []int
	globalYes         bool
	globalNo          bool
	globalAbstain     bool
	minAmount         int
	maxAmount         int
	maxVotesPerOption int
	options           []int
	state             string
}

func loadPoll(ctx context.Context, ds *dsfetch.Fetch, pollID int) (pollConfig, error) {
	p := pollConfig{id: pollID}
	ds.Poll_MeetingID(pollID).Lazy(&p.meetingID)
	ds.Poll_Backend(pollID).Lazy(&p.backend)
	ds.Poll_Type(pollID).Lazy(&p.pollType)
	ds.Poll_Pollmethod(pollID).Lazy(&p.method)
	ds.Poll_EntitledGroupIDs(pollID).Lazy(&p.groups)
	ds.Poll_GlobalYes(pollID).Lazy(&p.globalYes)
	ds.Poll_GlobalNo(pollID).Lazy(&p.globalNo)
	ds.Poll_GlobalAbstain(pollID).Lazy(&p.globalAbstain)
	ds.Poll_MinVotesAmount(pollID).Lazy(&p.minAmount)
	ds.Poll_MaxVotesAmount(pollID).Lazy(&p.maxAmount)
	ds.Poll_MaxVotesPerOption(pollID).Lazy(&p.maxVotesPerOption)
	ds.Poll_OptionIDs(pollID).Lazy(&p.options)
	ds.Poll_State(pollID).Lazy(&p.state)

	if err := ds.Execute(ctx); err != nil {
		return pollConfig{}, fmt.Errorf("loading polldata from datastore: %w", err)
	}

	return p, nil
}

// preload loads all data in the cache, that is needed later for the vote
// requests.
func (p pollConfig) preload(ctx context.Context, ds *dsfetch.Fetch) error {
	ds.Meeting_UsersEnableVoteWeight(p.meetingID)

	userIDsList := make([][]int, len(p.groups))
	for i, groupID := range p.groups {
		ds.Group_UserIDs(groupID).Lazy(&userIDsList[i])
	}

	// First database requesst to get meeting/enable_vote_weight and all users
	// from all entitled groups.
	if err := ds.Execute(ctx); err != nil {
		return fmt.Errorf("fetching users: %w", err)
	}

	for _, userIDs := range userIDsList {
		for _, userID := range userIDs {
			ds.User_GroupIDs(userID, p.meetingID)
			ds.User_VoteWeight(userID, p.meetingID)
			ds.User_DefaultVoteWeight(userID)
			ds.User_IsPresentInMeetingIDs(userID)
			ds.User_VoteDelegatedToID(userID, p.meetingID)
		}
	}

	// Second database request to get all users fetched above.
	if err := ds.Execute(ctx); err != nil {
		return fmt.Errorf("preloading present users: %w", err)
	}

	var delegatedUserIDs []int
	for _, userIDs := range userIDsList {
		for _, userID := range userIDs {
			// This does not send a db request, since the value was fetched in
			// the block above.
			delegatedUserID := ds.User_VoteDelegatedToID(userID, p.meetingID).ErrorLater(ctx)
			if delegatedUserID != 0 {
				delegatedUserIDs = append(delegatedUserIDs, delegatedUserID)
			}
		}
	}

	for _, userID := range delegatedUserIDs {
		ds.User_IsPresentInMeetingIDs(userID)
	}

	// Third database request to get the present state of delegated users that
	// are not in an entitled group. If there are equivalent users, no request
	// is send.
	if err := ds.Execute(ctx); err != nil {
		return fmt.Errorf("preloading delegated users: %w", err)
	}
	return nil
}

type maybeInt struct {
	unmarshalled bool
	value        int
}

func (m *maybeInt) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &m.value); err != nil {
		return fmt.Errorf("decoding value as int: %w", err)
	}
	m.unmarshalled = true
	return nil
}

func (m *maybeInt) Value() (int, bool) {
	return m.value, m.unmarshalled
}

type ballot struct {
	UserID maybeInt        `json:"user_id"`
	Value  json.RawMessage `json:"value"`
}

func (v ballot) String() string {
	bs, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("Error decoding ballot: %v", err)
	}
	return string(bs)
}

func isPresent(meetingID int, presentMeetings []int) bool {
	for _, present := range presentMeetings {
		if present == meetingID {
			return true
		}
	}
	return false
}

// equalElement returns true, if g1 and g2 have at lease one equal element.
func equalElement(g1, g2 []int) bool {
	set := make(map[int]bool, len(g1))
	for _, e := range g1 {
		set[e] = true
	}
	for _, e := range g2 {
		if set[e] {
			return true
		}
	}
	return false
}
