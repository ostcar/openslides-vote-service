package vote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsfetch"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsrecorder"
	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

// Decrypter decryptes the incomming votes.
type Decrypter interface {
	Start(ctx context.Context, pollID string) (pubKey []byte, pubKeySig []byte, err error)
	Stop(ctx context.Context, pollID string, voteList [][]byte) (decryptedContent, signature []byte, err error)
	Clear(ctx context.Context, pollID string) error
	PublicMainKey(ctx context.Context) ([]byte, error)
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

// backend returns the poll backend for a pollConfig object.
func (v *Vote) backend(p pollConfig) Backend {
	backend := v.longBackend
	if p.backend == "fast" {
		backend = v.fastBackend
	}
	log.Debug("Used backend: %v", backend)
	return backend
}

func (v *Vote) qualifiedID(ctx context.Context, fetch *dsfetch.Fetch, id int) (string, error) {
	rawURL, err := fetch.Organization_Url(1).Value(ctx)
	if err != nil {
		return "", fmt.Errorf("getting organization url: %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid url %s: %w", rawURL, err)
	}

	return fmt.Sprintf("%s/%d", parsed.Hostname(), id), nil
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

	recorder := dsrecorder.New(v.ds)
	ds := dsfetch.New(recorder)

	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading poll: %w", err)
	}

	if poll.ptype == "analog" {
		return nil, nil, MessageError{ErrInvalid, "Analog poll can not be started"}
	}

	if err := poll.preload(ctx, ds); err != nil {
		return nil, nil, fmt.Errorf("preloading data: %w", err)
	}
	log.Debug("Preload cache. Received keys: %v", recorder.Keys())

	backend := v.backend(poll)
	if err := backend.Start(ctx, pollID); err != nil {
		return nil, nil, fmt.Errorf("starting poll in the backend: %w", err)
	}

	if poll.ptype != "cryptographic" {
		return nil, nil, nil
	}

	defer func() {
		if err != nil {
			backend.Clear(ctx, pollID)
		}
	}()

	qid, err := v.qualifiedID(ctx, ds, pollID)
	if err != nil {
		return nil, nil, fmt.Errorf("building qualified id: %w", err)
	}

	pubkey, pubKeySig, err = v.decrypter.Start(ctx, qid)
	if err != nil {
		return nil, nil, fmt.Errorf("starting poll in decrypter: %w", err)
	}

	return pubkey, pubKeySig, nil
}

// StopResult is the return value from vote.Stop.
type StopResult struct {
	Votes     json.RawMessage
	Signature []byte
	UserIDs   []int
	Invalid   map[int]string
}

// Stop ends a poll.
//
// This method is idempotence. Many requests with the same pollID will return
// the same data. Calling vote.Clear will stop this behavior.
func (v *Vote) Stop(ctx context.Context, pollID int) (StopResult, error) {
	log.Debug("Receive stop event for poll %d", pollID)

	ds := dsfetch.New(v.ds)
	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return StopResult{}, fmt.Errorf("loading poll: %w", err)
	}

	backend := v.backend(poll)
	ballots, userIDs, err := backend.Stop(ctx, pollID)
	if err != nil {
		var errNotExist interface{ DoesNotExist() }
		if errors.As(err, &errNotExist) {
			return StopResult{}, MessageError{ErrNotExists, fmt.Sprintf("Poll %d does not exist in the backend", pollID)}
		}

		return StopResult{}, fmt.Errorf("fetching vote objects: %w", err)
	}

	switch poll.ptype {
	case "cryptographic":
		return v.stopCrypto(ctx, poll, ds, ballots, userIDs)
	default:
		return stopNonCrypto(ballots, userIDs)
	}
}

func stopNonCrypto(ballots [][]byte, userIDs []int) (StopResult, error) {
	encodable := make([]json.RawMessage, len(ballots))
	for i := range ballots {
		encodable[i] = ballots[i]
	}

	votes, err := json.Marshal(encodable)
	if err != nil {
		return StopResult{}, fmt.Errorf("encode votes to list: %w", err)
	}

	return StopResult{Votes: votes, UserIDs: userIDs}, nil
}

func (v *Vote) stopCrypto(ctx context.Context, poll pollConfig, ds *dsfetch.Fetch, ballots [][]byte, userIDs []int) (StopResult, error) {
	qid, err := v.qualifiedID(ctx, ds, poll.id)
	if err != nil {
		return StopResult{}, fmt.Errorf("building qualified id: %w", err)
	}

	voteValue := make([][]byte, len(ballots))
	for i := range ballots {
		// This uses the type `[]byte` to decode a base64 value.
		var vote struct {
			Value []byte `json:"value"`
		}
		if err := json.Unmarshal(ballots[i], &vote); err != nil {
			return StopResult{}, fmt.Errorf("decoding stored vote: %w", err)
		}

		voteValue[i] = vote.Value
	}

	decrypted, signature, err := v.decrypter.Stop(ctx, qid, voteValue)
	if err != nil {
		return StopResult{}, fmt.Errorf("decrypting votes: %w", err)
	}

	var decryptedContent struct {
		ID    string `json:"id"`
		Votes []struct {
			Votes ballotValue `json:"votes"`
		} `json:"votes"`
	}
	if err := json.Unmarshal(decrypted, &decryptedContent); err != nil {
		return StopResult{}, fmt.Errorf("encoding decrypted votes: %w", err)
	}

	invalid := make(map[int]string)
	for i, vote := range decryptedContent.Votes {
		if validation := validate(poll, vote.Votes); validation != "" {
			invalid[i] = validation
		}
	}

	return StopResult{Votes: decrypted, Signature: signature, UserIDs: userIDs, Invalid: invalid}, nil
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

	if v.decrypter == nil {
		return nil
	}

	if err := v.decrypter.Clear(ctx, qid); err != nil {
		return fmt.Errorf("clearing decrypter: %w", err)
	}

	return nil
}

// ClearAll removes all knowlage of all polls and the datastore-cache.
//
// This does not work for the vote decrypter.
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

	return nil
}

// Vote validates and saves the vote.
func (v *Vote) Vote(ctx context.Context, pollID, requestUser int, r io.Reader) error {
	log.Debug("Receive vote event for poll %d from user %d", pollID, requestUser)

	ds := dsfetch.New(v.ds)
	poll, err := loadPoll(ctx, ds, pollID)
	if err != nil {
		return fmt.Errorf("loading poll: %w", err)
	}
	log.Debug("Poll config: %v", poll)

	if err := ensurePresent(ctx, ds, poll.meetingID, requestUser); err != nil {
		return err
	}

	var vote ballot
	if err := json.NewDecoder(r).Decode(&vote); err != nil {
		return MessageError{ErrInvalid, fmt.Sprintf("decoding payload: %v", err)}
	}

	voteUser, exist := vote.UserID.Value()
	if !exist {
		voteUser = requestUser
	}

	if err := ensureVoteUser(ctx, ds, poll, voteUser, requestUser); err != nil {
		return err
	}

	var voteWeight string
	if poll.ptype != "cryptographic" {
		if validation := validate(poll, vote.Value); validation != "" {
			return MessageError{ErrInvalid, validation}
		}

		// voteData.Weight is a DecimalField with 6 zeros.
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
	}

	voteData := struct {
		RequestUser int             `json:"request_user_id,omitempty"`
		VoteUser    int             `json:"vote_user_id,omitempty"`
		Value       json.RawMessage `json:"value"`
		Weight      string          `json:"weight,omitempty"`
	}{
		requestUser,
		voteUser,
		vote.Value.original,
		voteWeight,
	}

	if poll.ptype != "named" {
		voteData.RequestUser = 0
		voteData.VoteUser = 0
	}

	bs, err := json.Marshal(voteData)
	if err != nil {
		return fmt.Errorf("decoding vote data: %w", err)
	}

	if err := v.backend(poll).Vote(ctx, pollID, voteUser, bs); err != nil {
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

// ensurePresent makes sure that the user sending the vote request is present.
func ensurePresent(ctx context.Context, ds *dsfetch.Fetch, meetingID, user int) error {
	presentMeetings, err := ds.User_IsPresentInMeetingIDs(user).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching is present in meetings: %w", err)
	}

	for _, present := range presentMeetings {
		if present == meetingID {
			return nil
		}
	}
	return MessageError{ErrNotAllowed, fmt.Sprintf("You have to be present in meeting %d", meetingID)}
}

// ensureVoteUser makes sure the user from the vote:
// * is not anonymous,
// * the delegation is correct and
// * is in the correct group
func ensureVoteUser(ctx context.Context, ds *dsfetch.Fetch, poll pollConfig, voteUser, requestUser int) error {
	if voteUser == 0 {
		return MessageError{ErrNotAllowed, "Votes for anonymous user are not allowed"}
	}

	groupIDs, err := ds.User_GroupIDs(voteUser, poll.meetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching groups of user %d in meeting %d: %w", voteUser, poll.meetingID, err)
	}

	if !equalElement(groupIDs, poll.groups) {
		return MessageError{ErrNotAllowed, fmt.Sprintf("User %d is not in a group that is allowed to vote", voteUser)}
	}

	if voteUser == requestUser {
		return nil
	}

	delegationActivated, err := ds.Meeting_UsersEnableVoteDelegations(poll.meetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching user enable vote delegation: %w", err)
	}

	if !delegationActivated {
		return MessageError{ErrNotAllowed, fmt.Sprintf("Vote delegation is not activated in meeting %d", poll.meetingID)}
	}

	log.Debug("Vote delegation")
	delegation, err := ds.User_VoteDelegatedToID(voteUser, poll.meetingID).Value(ctx)
	if err != nil {
		return fmt.Errorf("fetching delegation from user %d in meeting %d: %w", voteUser, poll.meetingID, err)
	}

	if delegation != requestUser {
		return MessageError{ErrNotAllowed, fmt.Sprintf("You can not vote for user %d", voteUser)}
	}

	return nil
}

// VotedPolls tells, on which the requestUser has already voted.
func (v *Vote) VotedPolls(ctx context.Context, pollIDs []int, requestUser int) (map[int][]int, error) {
	log.Debug("Receive voted event for polls %v from user %d", pollIDs, requestUser)

	ds := dsfetch.New(v.ds)

	userIDs, err := delegatedUserIDs(ctx, ds, requestUser)
	if err != nil {
		return nil, fmt.Errorf("getting all delegated users: %w", err)
	}
	userIDs = append([]int{requestUser}, userIDs...)

	polls := make([]pollConfig, 0, len(pollIDs))
	for _, pid := range pollIDs {
		poll, err := loadPoll(ctx, ds, pid)
		if err != nil {
			var errDoesNotExist dsfetch.DoesNotExistError
			if errors.As(err, &errDoesNotExist) && errDoesNotExist.Collection == "poll" {
				continue
			}
			return nil, fmt.Errorf("loading poll: %w", err)
		}

		polls = append(polls, poll)
	}

	backendPollIDs, err := v.pollsByBackend(polls)
	if err != nil {
		return nil, fmt.Errorf("sorting polls by its backend: %w", err)
	}

	result := make(map[int][]int)
	for backend, pids := range backendPollIDs {
		voted, err := backend.VotedPolls(ctx, pids, userIDs)
		if err != nil {
			return nil, fmt.Errorf("voted polls for backend %s: %w", backend, err)
		}
		for pid, userIDs := range voted {
			result[pid] = userIDs
		}
	}

	for _, pid := range pollIDs {
		if _, ok := result[pid]; !ok {
			result[pid] = nil
		}
	}

	return result, nil
}

// polls order a list of pollIDs by its backend.
func (v *Vote) pollsByBackend(polls []pollConfig) (map[Backend][]int, error) {
	backendPollIDs := map[Backend][]int{
		v.longBackend: nil,
		v.fastBackend: nil,
	}

	for _, poll := range polls {
		backendPollIDs[v.backend(poll)] = append(backendPollIDs[v.backend(poll)], poll.id)
	}

	return backendPollIDs, nil
}

// delegatedUserIDs returns all user ids for which the user can vote.
func delegatedUserIDs(ctx context.Context, fetch *dsfetch.Fetch, userID int) ([]int, error) {
	meetingIDs, err := fetch.User_VoteDelegationsFromIDsTmpl(userID).Value(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting vote_delegation_from template field: %w", err)
	}

	meetingUserIDs := make([][]int, len(meetingIDs))
	for i, mid := range meetingIDs {
		fetch.User_VoteDelegationsFromIDs(userID, mid).Lazy(&meetingUserIDs[i])
	}

	if err := fetch.Execute(ctx); err != nil {
		return nil, fmt.Errorf("getting vote_delegation_from values: %w", err)
	}

	var uids []int
	for _, muids := range meetingUserIDs {
		uids = append(uids, muids...)
	}

	return uids, nil
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

// CryptoPublicMainKey returns the public main key from vote-decrypt.
func (v *Vote) CryptoPublicMainKey(ctx context.Context) ([]byte, error) {
	if v.decrypter == nil {
		return nil, fmt.Errorf("decrypt service is not configured")
	}

	return v.decrypter.PublicMainKey(ctx)
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

	// VotedPolls tells for a list of poll IDs if the any of the given userIDs
	// has already voted.
	VotedPolls(ctx context.Context, pollIDs []int, userIDs []int) (map[int][]int, error)

	// VoteCount returns the amout of votes for each vote in the backend.
	VoteCount(ctx context.Context) (map[int]int, error)

	fmt.Stringer
}

type pollConfig struct {
	id                int
	meetingID         int
	backend           string
	ptype             string
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
	ds.Poll_Type(pollID).Lazy(&p.ptype)
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
	ds.Meeting_UsersEnableVoteDelegations(p.meetingID)

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
	UserID maybeInt    `json:"user_id"`
	Value  ballotValue `json:"value"`
}

func (v ballot) String() string {
	bs, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("Error decoding ballot: %v", err)
	}
	return string(bs)
}

func validate(poll pollConfig, v ballotValue) string {
	if poll.minAmount == 0 {
		poll.minAmount = 1
	}

	if poll.maxAmount == 0 {
		poll.maxAmount = 1
	}

	if poll.maxVotesPerOption == 0 {
		poll.maxVotesPerOption = 1
	}

	allowedOptions := make(map[int]bool, len(poll.options))
	for _, o := range poll.options {
		allowedOptions[o] = true
	}

	allowedGlobal := map[string]bool{
		"Y": poll.globalYes,
		"N": poll.globalNo,
		"A": poll.globalAbstain,
	}

	var voteIsValid string

	switch poll.method {
	case "Y", "N":
		switch v.Type() {
		case ballotValueString:
			// The user answered with Y, N or A (or another invalid string).
			if !allowedGlobal[v.str] {
				return fmt.Sprintf("Global vote %s is not enabled", v.str)
			}
			return voteIsValid

		case ballotValueOptionAmount:
			var sumAmount int
			for optionID, amount := range v.optionAmount {
				if amount < 0 {
					return fmt.Sprintf("Your vote for option %d has to be >= 0", optionID)
				}

				if amount > poll.maxVotesPerOption {
					return fmt.Sprintf("Your vote for option %d has to be <= %d", optionID, poll.maxVotesPerOption)
				}

				if !allowedOptions[optionID] {
					return fmt.Sprintf("Option_id %d does not belong to the poll", optionID)
				}

				sumAmount += amount
			}

			if sumAmount < poll.minAmount || sumAmount > poll.maxAmount {
				return fmt.Sprintf("The sum of your answers has to be between %d and %d", poll.minAmount, poll.maxAmount)
			}

			return voteIsValid

		default:
			return fmt.Sprintf("Your vote has a wrong format for poll method Y or N")
		}

	case "YN", "YNA":
		switch v.Type() {
		case ballotValueString:
			// The user answered with Y, N or A (or another invalid string).
			if !allowedGlobal[v.str] {
				return fmt.Sprintf("Global vote %s is not enabled", v.str)
			}
			return voteIsValid

		case ballotValueOptionString:
			for optionID, yna := range v.optionYNA {
				if !allowedOptions[optionID] {
					return fmt.Sprintf("Option_id %d does not belong to the poll", optionID)
				}

				if yna != "Y" && yna != "N" && (yna != "A" || poll.method != "YNA") {
					// Valid that given data matches poll method.
					return fmt.Sprintf("Data for option %d does not fit the poll method.", optionID)
				}
			}
			return voteIsValid

		default:
			return fmt.Sprintf("Your vote has a wrong format for poll method YN or YNA")
		}

	default:
		return fmt.Sprintf("Invalid poll method")
	}
}

// voteData is the data a user sends as his vote.
type ballotValue struct {
	str          string
	optionAmount map[int]int
	optionYNA    map[int]string

	original json.RawMessage
}

func (v ballotValue) MarshalJSON() ([]byte, error) {
	return v.original, nil
}

func (v *ballotValue) UnmarshalJSON(b []byte) error {
	v.original = b

	if err := json.Unmarshal(b, &v.str); err == nil {
		// voteData is a string
		return nil
	}

	if err := json.Unmarshal(b, &v.optionAmount); err == nil {
		// voteData is option_id to amount
		return nil
	}
	v.optionAmount = nil

	if err := json.Unmarshal(b, &v.optionYNA); err == nil {
		// voteData is option_id to string
		return nil
	}

	return fmt.Errorf("unknown vote value: `%s`", b)
}

const (
	ballotValueUnknown = iota
	ballotValueString
	ballotValueOptionAmount
	ballotValueOptionString
)

func (v *ballotValue) Type() int {
	if v.str != "" {
		return ballotValueString
	}

	if v.optionAmount != nil {
		return ballotValueOptionAmount
	}

	if v.optionYNA != nil {
		return ballotValueOptionString
	}

	return ballotValueUnknown
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
