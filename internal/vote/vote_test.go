package vote_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsmock"
	"github.com/OpenSlides/openslides-vote-service/internal/backends/memory"
	"github.com/OpenSlides/openslides-vote-service/internal/vote"
)

func TestVoteStart(t *testing.T) {
	t.Run("Not started poll", func(t *testing.T) {
		backend := memory.New()
		ds := dsmock.NewMockDatastore(dsmock.YAMLData(`
		organization/1/url: test.com
		poll:
			1:
				meeting_id: 5
				state: started

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		meeting/5/id: 5
		`))

		v := vote.New(backend, backend, ds, new(decrypterStub))

		if _, _, err := v.Start(context.Background(), 1); err != nil {
			t.Errorf("Start returned unexpected error: %v", err)
		}

		if c := len(ds.Requests()); c > 3 {
			t.Errorf("Start used %d requests to the datastore, expected max 2: %v", c, ds.Requests())
		}

		// After a poll was started, it has to be possible to send votes.
		if err := backend.Vote(context.Background(), 1, 1, []byte("something")); err != nil {
			t.Errorf("Vote after start retuen and unexpected error: %v", err)
		}
	})

	t.Run("Start poll a second time", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		organization/1/url: test.com
		poll:
			1:
				meeting_id: 5
				type: named
				state: started

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		meeting/5/id: 5
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))
		v.Start(context.Background(), 1)

		if _, _, err := v.Start(context.Background(), 1); err != nil {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	})

	t.Run("Start a stopped poll", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		organization/1/url: test.com
		poll:
			1:
				meeting_id: 5
				type: named
				state: started

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		meeting/5/id: 5
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))
		v.Start(context.Background(), 1)

		if _, _, err := backend.Stop(context.Background(), 1); err != nil {
			t.Fatalf("Stop returned unexpected error: %v", err)
		}

		if _, _, err := v.Start(context.Background(), 1); err != nil {
			t.Errorf("Start returned unexpected error: %v", err)
		}
	})

	t.Run("Start an anolog poll", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		poll:
			1:
				meeting_id: 5
				type: analog
				state: started

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))

		_, _, err := v.Start(context.Background(), 1)

		if err == nil {
			t.Errorf("Got no error, expected `Some error`")
		}
	})

	t.Run("Start an poll in `wrong` state", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		organization/1/url: test.com
		poll:
			1:
				meeting_id: 5
				type: named
				state: created

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		meeting/5/id: 5
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))

		_, _, err := v.Start(context.Background(), 1)

		if err != nil {
			t.Errorf("Start returned: %v", err)
		}
	})

	t.Run("Start an finished poll", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		poll:
			1:
				meeting_id: 5
				type: named
				state: finished

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))

		_, _, err := v.Start(context.Background(), 1)

		if err == nil {
			t.Errorf("Got no error, expected `Some error`")
		}
	})

	t.Run("Start an finished poll", func(t *testing.T) {
		backend := memory.New()
		ds := StubGetter{data: dsmock.YAMLData(`
		poll:
			1:
				meeting_id: 5
				type: named
				state: published

		group/1/user_ids: [1]
		user/1/is_present_in_meeting_ids: [1]
		`)}
		v := vote.New(backend, backend, &ds, new(decrypterStub))

		_, _, err := v.Start(context.Background(), 1)

		if err == nil {
			t.Errorf("Got no error, expected `Some error`")
		}
	})
}

func TestVoteStartPreloadData(t *testing.T) {
	backend := memory.New()
	ds := dsmock.NewMockDatastore(dsmock.YAMLData(`
	organization/1/url: test.com
	poll/1:
		meeting_id: 5
		entitled_group_ids: [1]
		state: started
	
	group:
		1:
			user_ids: [1,2]
	user:
		1:
			is_present_in_meeting_ids: [1]
		2:
			is_present_in_meeting_ids: [1]
	meeting/5/id: 5
	`))
	v := vote.New(backend, backend, ds, new(decrypterStub))

	if _, _, err := v.Start(context.Background(), 1); err != nil {
		t.Errorf("Start returned unexpected error: %v", err)
	}

	if !ds.KeysRequested(MustKey("poll/1/meeting_id"), MustKey("user/1/is_present_in_meeting_ids"), MustKey("user/2/is_present_in_meeting_ids")) {
		t.Fatalf("Not all keys where preloaded.")
	}
}

func TestVoteStartDSError(t *testing.T) {
	backend := memory.New()
	ds := StubGetter{err: errors.New("Some error")}
	v := vote.New(backend, backend, &ds, new(decrypterStub))
	_, _, err := v.Start(context.Background(), 1)

	if err == nil {
		t.Errorf("Got no error, expected `Some error`")
	}
}

func TestVoteStop(t *testing.T) {
	backend := memory.New()
	v := vote.New(backend, backend, &StubGetter{data: dsmock.YAMLData(`
	organization/1/url: test.com
	poll/1/meeting_id: 1
	poll/2/meeting_id: 1
	poll/3/meeting_id: 1
	`)}, new(decrypterStub))

	t.Run("Unknown poll", func(t *testing.T) {
		_, _, _, err := v.Stop(context.Background(), 1)

		if !errors.Is(err, vote.ErrNotExists) {
			t.Errorf("Stopping an unknown poll has to return an ErrNotExists, got: %v", err)
		}
	})

	t.Run("Known poll", func(t *testing.T) {
		if err := backend.Start(context.Background(), 2); err != nil {
			t.Fatalf("Start returned an unexpected error: %v", err)
		}

		backend.Vote(context.Background(), 2, 1, []byte(`{"value":"polldata1"}`))
		backend.Vote(context.Background(), 2, 2, []byte(`{"value":"polldata2"}`))

		votes, _, userIDs, err := v.Stop(context.Background(), 2)
		if err != nil {
			t.Fatalf("Stop returned unexpected error: %v", err)
		}

		expected := `[{"value":"polldata1"},{"value":"polldata2"}]`
		if string(votes) != expected {
			t.Errorf("Got votes %s, expected %s", votes, expected)
		}

		if !reflect.DeepEqual(userIDs, []int{1, 2}) {
			t.Errorf("Got users %v, expected [1 2]", userIDs)
		}

		err = backend.Vote(context.Background(), 2, 3, []byte(`"polldata3"`))
		var errStopped interface{ Stopped() }
		if !errors.As(err, &errStopped) {
			t.Errorf("Stop did not stop the poll in the backend.")
		}
	})

	t.Run("Poll without data", func(t *testing.T) {
		if err := backend.Start(context.Background(), 3); err != nil {
			t.Fatalf("Start returned an unexpected error: %v", err)
		}

		votes, _, userIDs, err := v.Stop(context.Background(), 3)
		if err != nil {
			t.Fatalf("Stop returned unexpected error: %v", err)
		}

		if string(votes) != `[]` {
			t.Errorf("Got votes %s, expected []", votes)
		}

		if len(userIDs) != 0 {
			t.Errorf("Got userIDs %v, expected []", userIDs)
		}
	})
}

func TestVoteClear(t *testing.T) {
	data := &StubGetter{data: dsmock.YAMLData(`organization/1/url: test.com`)}
	backend := memory.New()
	v := vote.New(backend, backend, data, new(decrypterStub))

	if err := v.Clear(context.Background(), 1); err != nil {
		t.Fatalf("Clear returned unexpected error: %v", err)
	}
}

func TestVoteClearAll(t *testing.T) {
	backend := memory.New()
	v := vote.New(backend, backend, &StubGetter{}, new(decrypterStub))

	if err := v.ClearAll(context.Background()); err != nil {
		t.Fatalf("ClearAll returned unexpected error: %v", err)
	}
}

func TestVoteVote(t *testing.T) {
	backend := memory.New()
	v := vote.New(backend, backend, &StubGetter{
		data: dsmock.YAMLData(`
		poll/1:
			meeting_id: 1
			entitled_group_ids: [1]
			pollmethod: Y
			global_yes: true
		
		meeting/1/id: 1

		user/1:
			is_present_in_meeting_ids: [1]
			group_$1_ids: [1]
		`),
	}, new(decrypterStub))

	t.Run("Unknown poll", func(t *testing.T) {
		err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{"value":"Y"}`))

		if !errors.Is(err, vote.ErrNotExists) {
			t.Errorf("Expected ErrNotExists, got: %v", err)
		}
	})

	if err := backend.Start(context.Background(), 1); err != nil {
		t.Fatalf("Starting poll returned unexpected error: %v", err)
	}

	t.Run("Invalid json", func(t *testing.T) {
		err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{123`))

		var errTyped vote.TypeError
		if !errors.As(err, &errTyped) {
			t.Fatalf("Vote() did not return an TypeError, got: %v", err)
		}

		if errTyped != vote.ErrInvalid {
			t.Errorf("Got error type `%s`, expected `%s`", errTyped.Type(), vote.ErrInvalid.Type())
		}
	})

	t.Run("Valid data", func(t *testing.T) {
		err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{"value":"Y"}`))
		if err != nil {
			t.Fatalf("Vote returned unexpected error: %v", err)
		}

	})

	t.Run("User has voted", func(t *testing.T) {
		err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{"value":"Y"}`))
		if err == nil {
			t.Fatalf("Vote returned no error")
		}

		var errTyped vote.TypeError
		if !errors.As(err, &errTyped) {
			t.Fatalf("Vote() did not return an TypeError, got: %v", err)
		}

		if errTyped != vote.ErrDoubleVote {
			t.Errorf("Got error type `%s`, expected `%s`", errTyped.Type(), vote.ErrDoubleVote.Type())
		}
	})

	t.Run("Poll is stopped", func(t *testing.T) {
		backend.Stop(context.Background(), 1)

		err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{"value":"Y"}`))
		if err == nil {
			t.Fatalf("Vote returned no error")
		}

		var errTyped vote.TypeError
		if !errors.As(err, &errTyped) {
			t.Fatalf("Vote() did not return an TypeError, got: %v", err)
		}

		if errTyped != vote.ErrStopped {
			t.Errorf("Got error type `%s`, expected `%s`", errTyped.Type(), vote.ErrStopped.Type())
		}
	})
}

func TestVoteNoRequests(t *testing.T) {
	// Makes sure, that a a vote does not do any database requests.

	for _, tt := range []struct {
		name string
		data string
		vote string
	}{
		{
			"normal vote",
			`---
			organization/1/url: test.com
			poll/1:
				meeting_id: 50
				entitled_group_ids: [5]
				pollmethod: Y
				global_yes: true
				state: started
			
			meeting/50/id: 50

			user/1:
				is_present_in_meeting_ids: [50]
				group_$50_ids: [5]

			group/5/user_ids: [1]
			`,
			`{"value":"Y"}`,
		},
		{
			"delegation vote",
			`---
			organization/1/url: test.com
			poll/1:
				meeting_id: 50
				entitled_group_ids: [5]
				pollmethod: Y
				global_yes: true
				state: started
			
			meeting/50/id: 50

			user:
				1:
					is_present_in_meeting_ids: [50]
				2:
					group_$50_ids: [5]
					vote_delegated_$50_to_id: 1

			group/5/user_ids: [2]
			`,
			`{"user_id":2,"value":"Y"}`,
		},
		{
			"vote weight enabled",
			`---
			organization/1/url: test.com
			poll/1:
				meeting_id: 50
				entitled_group_ids: [5]
				pollmethod: Y
				global_yes: true
				state: started
			
			meeting/50/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [50]
				group_$50_ids: [5]

			group/5/user_ids: [1]
			`,
			`{"value":"Y"}`,
		},
		{
			"vote weight enabled and delegated",
			`---
			organization/1/url: test.com
			poll/1:
				meeting_id: 50
				entitled_group_ids: [5]
				pollmethod: Y
				global_yes: true
				state: started
			
			meeting/50/users_enable_vote_weight: true

			user:
				1:
					is_present_in_meeting_ids: [50]
				2:
					group_$50_ids: [5]
					vote_delegated_$50_to_id: 1

			group/5/user_ids: [2]
			`,
			`{"user_id":2,"value":"Y"}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := dsmock.NewMockDatastore(dsmock.YAMLData(tt.data))
			backend := memory.New()
			v := vote.New(backend, backend, ds, new(decrypterStub))

			if _, _, err := v.Start(context.Background(), 1); err != nil {
				t.Fatalf("Can not start poll: %v", err)
			}

			ds.ResetRequests()

			if err := v.Vote(context.Background(), 1, 1, strings.NewReader(tt.vote)); err != nil {
				t.Errorf("Vote returned unexpected error: %v", err)
			}

			if len(ds.Requests()) != 0 {
				t.Errorf("Vote send %d requests to the datastore: %v", len(ds.Requests()), ds.Requests())
			}
		})
	}
}

func TestVoteDelegationAndGroup(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
		vote string

		expectVotedUserID int
	}{
		{
			"Not delegated",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
			`,
			`{"value":"Y"}`,

			1,
		},

		{
			"Not delegated not present",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1				

			user/1:
				is_present_in_meeting_ids: []
				group_$1_ids: [1]
			`,
			`{"value":"Y"}`,

			0,
		},

		{
			"Not delegated not in group",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: []
			`,
			`{"value":"Y"}`,

			0,
		},

		{
			"Vote for self",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true
			
			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
			`,
			`{"user_id": 1, "value":"Y"}`,

			1,
		},

		{
			"Vote for anonymous",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true
			
			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
			`,
			`{"user_id": 0, "value":"Y"}`,

			0,
		},

		{
			"Vote for other without delegation",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1

			user/1/is_present_in_meeting_ids: [1]
			user/2/group_$1_ids: [1]
			`,
			`{"user_id": 2, "value":"Y"}`,

			0,
		},

		{
			"Vote for other with delegation",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1

			user/1/is_present_in_meeting_ids: [1]
			user/2:
				vote_delegated_$1_to_id: 1
				group_$1_ids: [1]
			`,
			`{"user_id": 2, "value":"Y"}`,

			2,
		},

		{
			"Vote for other with delegation not in group",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true
			
			meeting/1/id: 1

			user/1/is_present_in_meeting_ids: [1]
			user/2:
				vote_delegated_$1_to_id: 1
				group_$1_ids: []
			`,
			`{"user_id": 2, "value":"Y"}`,

			0,
		},

		{
			"Vote for other with self not in group",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true
			
			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: []

			user/2:
				vote_delegated_$1_to_id: 1
				group_$1_ids: [1]
			`,
			`{"user_id": 2, "value":"Y"}`,

			2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend := memory.New()
			v := vote.New(backend, backend, &StubGetter{data: dsmock.YAMLData(tt.data)}, new(decrypterStub))
			backend.Start(context.Background(), 1)

			err := v.Vote(context.Background(), 1, 1, strings.NewReader(tt.vote))

			if tt.expectVotedUserID != 0 {
				if err != nil {
					t.Fatalf("Vote returned unexpected error: %v", err)
				}

				backend.AssertUserHasVoted(t, 1, tt.expectVotedUserID)
				return
			}

			if !errors.Is(err, vote.ErrNotAllowed) {
				t.Fatalf("Expected NotAllowedError, got: %v", err)
			}
		})
	}
}

func TestVoteWeight(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string

		expectWeight string
	}{
		{
			"No weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
			`,
			"1.000000",
		},
		{
			"Weight enabled, user has no weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
			`,
			"1.000000",
		},
		{
			"Weight enabled, user has default weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
				default_vote_weight: "2.000000"
			`,
			"2.000000",
		},
		{
			"Weight enabled, user has default weight and meeting weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
				default_vote_weight: "2.000000"
				vote_weight_$: [1]
				vote_weight_$1: "3.000000"
			`,
			"3.000000",
		},
		{
			"Weight enabled, user has default weight and meeting weight in other meeting",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				pollmethod: Y
				global_yes: true

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				group_$1_ids: [1]
				default_vote_weight: "2.000000"
				vote_weight_$: [2]
				vote_weight_$2: "3.000000"
			`,
			"2.000000",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend := memory.New()
			v := vote.New(backend, backend, &StubGetter{data: dsmock.YAMLData(tt.data)}, new(decrypterStub))
			backend.Start(context.Background(), 1)

			if err := v.Vote(context.Background(), 1, 1, strings.NewReader(`{"value":"Y"}`)); err != nil {
				t.Fatalf("vote returned unexpected error: %v", err)
			}

			data, _, _ := backend.Stop(context.Background(), 1)

			if len(data) != 1 {
				t.Fatalf("got %d vote objects, expected one", len(data))
			}

			var decoded struct {
				Weight string `json:"weight"`
			}
			if err := json.Unmarshal(data[0], &decoded); err != nil {
				t.Fatalf("decoding voteobject returned unexpected error: %v", err)
			}

			if decoded.Weight != tt.expectWeight {
				t.Errorf("got weight %q, expected %q", decoded.Weight, tt.expectWeight)
			}
		})
	}
}

func TestVotedPolls(t *testing.T) {
	backend := memory.New()
	ds := dsmock.Stub(dsmock.YAMLData(`---
	poll/1/backend: memory
	`))
	v := vote.New(backend, backend, ds, new(decrypterStub))
	backend.Start(context.Background(), 1)
	backend.Vote(context.Background(), 1, 5, []byte(`"Y"`))
	buf := new(bytes.Buffer)

	if err := v.VotedPolls(context.Background(), []int{1, 2}, 5, buf); err != nil {
		t.Fatalf("VotedPolls() returned unexected error: %v", err)
	}

	expect := `{"1":true,"2":false}` + "\n"
	if buf.String() != expect {
		t.Errorf("VotedPolls() wrote `%s`, expected `%s`", strings.TrimSpace(buf.String()), expect)
	}
}

func TestVoteCount(t *testing.T) {
	backend1 := memory.New()
	backend1.Start(context.Background(), 23)
	backend1.Vote(context.Background(), 23, 1, []byte("vote"))
	backend2 := memory.New()
	backend2.Start(context.Background(), 42)
	backend2.Vote(context.Background(), 42, 1, []byte("vote"))
	backend2.Vote(context.Background(), 42, 2, []byte("vote"))
	ds := dsmock.Stub(dsmock.YAMLData(``))

	v := vote.New(backend1, backend2, ds, new(decrypterStub))

	count, err := v.VoteCount(context.Background())
	if err != nil {
		t.Fatalf("VoteCount: %v", err)
	}

	expect := map[int]int{23: 1, 42: 2}
	if !reflect.DeepEqual(count, expect) {
		t.Errorf("Got %v, expected %v", count, expect)
	}
}
