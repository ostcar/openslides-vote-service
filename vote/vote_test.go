package vote_test

import (
	"errors"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/OpenSlides/openslides-go/datastore/dsfetch"
	"github.com/OpenSlides/openslides-go/datastore/dskey"
	"github.com/OpenSlides/openslides-go/datastore/dsmock"
	"github.com/OpenSlides/openslides-go/datastore/dsmodels"
	"github.com/OpenSlides/openslides-go/datastore/flow"
	"github.com/OpenSlides/openslides-go/datastore/pgtest"
	"github.com/OpenSlides/openslides-go/environment"
	"github.com/OpenSlides/openslides-vote-service/vote"
	"github.com/OpenSlides/openslides-vote-service/vote/method"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.RunTests(m))
}

func TestAll(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	organization/1/enable_electronic_voting: true
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30]

	user:
		5:
			username: admin
			organization_management_level: superadmin
		30:
			username: tom
	meeting_user/300:
		group_ids: [40]
		user_id: 30
		meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	group/41:
		name: wrong group
		meeting_id: 1
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Create", func(t *testing.T) {
				body := `{
					"title": "my pol",
					"content_object_id": "motion/5",
					"method": "approval",
					"method_config": {
						"onehundred_percent_base": "valid"
					},
					"visibility": "open",
					"meeting_id": 1,
					"entitled_group_ids": [41]
				}`

				id, err := service.Create(ctx, 5, strings.NewReader(body))
				if err != nil {
					t.Fatalf("Error creating poll: %v", err)
				}

				if id != 1 {
					t.Errorf("Expected id 1, got %d", id)
				}

				key := dskey.MustKey("poll/1/title")
				result, err := flow.Get(ctx, key)
				if err != nil {
					t.Fatalf("Error getting title from created poll: %v", err)
				}

				if string(result[key]) != `"my pol"` {
					t.Errorf("Expected title 'my poll', got %s", result[key])
				}
			})

			t.Run("Update", func(t *testing.T) {
				body := `{
					"title": "my poll",
					"entitled_group_ids": [40]
				}`

				err := service.Update(ctx, 1, 5, strings.NewReader(body))
				if err != nil {
					t.Fatalf("Error creating poll: %v", err)
				}

				poll, err := dsmodels.New(flow).Poll(1).First(ctx)
				if err != nil {
					t.Fatalf("fetch poll: %v", err)
				}

				if poll.Title != `my poll` {
					t.Errorf("Expected title 'my poll', got %s", poll.Title)
				}

				if len(poll.EntitledGroupIDs) != 1 && poll.EntitledGroupIDs[0] != 40 {
					t.Errorf("Expected entitled_group_ids [40], got %v", poll.EntitledGroupIDs)
				}
			})

			t.Run("Start", func(t *testing.T) {
				if err := service.Start(ctx, 1, 5); err != nil {
					t.Fatalf("Error starting poll: %v", err)
				}

				key := dskey.MustKey("poll/1/state")
				values, err := flow.Get(ctx, key)
				if err != nil {
					t.Fatalf("Error getting state from poll: %v", err)
				}

				if string(values[key]) != `"started"` {
					t.Errorf("Expected state to be started, got %s", values[key])
				}
			})

			t.Run("Vote", func(t *testing.T) {
				body := `{"value":"Yes"}`
				if err := service.Vote(ctx, 1, 30, strings.NewReader(body)); err != nil {
					t.Fatalf("Error voting on poll: %v", err)
				}

				ds := dsmodels.New(flow)
				ballot, err := ds.PollBallot(1).First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot: %v", err)
				}

				ballotUser, err := ds.PollBallotUser(1).First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot_user: %v", err)
				}

				if v, ok := ballotUser.ActingMeetingUserID.Value(); ok && v != 300 {
					t.Errorf("Expected acting meeting_user ID to be 300, got %d", v)
				}

				if ballot.Value != `"Yes"` {
					t.Errorf("Expected vote value to be '\"Yes\"', got '%s'", ballot.Value)
				}
			})

			t.Run("Finalize", func(t *testing.T) {
				if err := service.Finalize(ctx, 1, 5, false, false); err != nil {
					t.Fatalf("Error finalizing poll: %v", err)
				}

				keyState := dskey.MustKey("poll/1/state")
				keyResult := dskey.MustKey("poll/1/result")
				values, err := flow.Get(ctx, keyState, keyResult)
				if err != nil {
					t.Fatalf("Error getting state from poll: %v", err)
				}

				if string(values[keyState]) != `"finished"` {
					t.Errorf("Expected state to be finished, got %s", values[keyState])
				}

				if string(values[keyResult]) == `` {
					t.Errorf("Expected result to be set")
				}
			})

			t.Run("Publish", func(t *testing.T) {
				if err := service.Finalize(ctx, 1, 5, true, false); err != nil {
					t.Fatalf("Error publishing poll: %v", err)
				}

				key := dskey.MustKey("poll/1/published")
				values, err := flow.Get(ctx, key)
				if err != nil {
					t.Fatalf("Error getting state from poll: %v", err)
				}

				if string(values[key]) != `true` {
					t.Errorf("Expected published to be true, got %s", values[key])
				}
			})

			t.Run("Anonymize", func(t *testing.T) {
				if err := service.Finalize(ctx, 1, 5, true, true); err != nil {
					t.Fatalf("Error anonymizing poll: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(1)
				q = q.Preload(q.BallotList())
				poll, err := q.First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting poll with ballot: %v", err)
				}

				if len(poll.BallotList) == 0 {
					t.Fatalf("poll has no ballots")
				}
				ballot := poll.BallotList[0]

				if id, set := ballot.PollBallotUserID.Value(); set {
					t.Errorf("Expected ballot.poll_ballot_user_id not to be set, but it is to %d", id)
				}

				if !poll.Anonymized {
					t.Errorf("Expected poll to be anonymized")
				}
			})

			t.Run("Reset", func(t *testing.T) {
				if err := service.Reset(ctx, 1, 5); err != nil {
					t.Fatalf("Error resetting poll: %v", err)
				}

				key := dskey.MustKey("poll/1/state")
				values, err := flow.Get(ctx, key)
				if err != nil {
					t.Fatalf("Error getting state from poll: %v", err)
				}

				if string(values[key]) != `"created"` {
					t.Errorf("Expected state to be created, got %s", values[key])
				}

				ds := dsmodels.New(flow)
				anonymized, err := ds.Poll_Anonymized(1).Value(t.Context())
				if err != nil {
					t.Fatalf("Error: %v", err)
				}
				if anonymized {
					t.Errorf("Expected poll not to be anonymized")
				}
			})

			t.Run("Delete", func(t *testing.T) {
				if err := service.Delete(ctx, 1, 5); err != nil {
					t.Fatalf("Error deleting poll: %v", err)
				}

				key := dskey.MustKey("poll/1/title")
				_, err := flow.Get(ctx, key)
				if err != nil {
					t.Fatalf("Error getting title from created poll: %v", err)
				}
			})
		},
	)
}

func TestCreateSelection(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	organization/1/enable_electronic_voting: true
	user/5:
		username: admin
		organization_management_level: superadmin

	assignment/5:
		meeting_id: 1
		title: my assignment

	list_of_speakers/7:
		content_object_id: assignment/5
		sequential_number: 1
		meeting_id: 1

	meeting/1/welcome_title: hello world
	`

	withData(t, pg, data, func(service *vote.Vote, flow flow.Flow) {
		body := `{
			"title": "my poll",
			"content_object_id": "assignment/5",
			"method": "selection",
			"method_config": {
				"onehundred_percent_base": "valid",
				"min_options_amount": 1,
				"max_options_amount": 2
			},
			"visibility": "open",
			"meeting_id": 1,
			"options": ["Hubert", "Max"],
			"option_type": "text"
		}`

		id, err := service.Create(ctx, 5, strings.NewReader(body))
		if err != nil {
			t.Fatalf("Error creating poll: %v", err)
		}

		poll, err := dsmodels.New(flow).Poll(id).First(ctx)
		if err != nil {
			t.Fatalf("Fetch poll: %v", err)
		}

		_, configIDRaw, ok := strings.Cut(poll.ConfigID, "/")
		if !ok {
			t.Fatalf("invalid configID: %s", poll.ConfigID)
		}

		configID, err := strconv.Atoi(configIDRaw)
		if err != nil {
			t.Fatalf("invalid configID: %s", poll.ConfigID)
		}

		config, err := dsmodels.New(flow).PollConfigSelection(configID).First(ctx)
		if err != nil {
			t.Fatalf("Fetch poll config: %v", err)
		}

		if config.MaxOptionsAmount != 2 {
			t.Errorf("got max_options_amount %d, expected 2", config.MaxOptionsAmount)
		}

		if config.MinOptionsAmount != 1 {
			t.Errorf("got min_options_amount %d, expected 1", config.MinOptionsAmount)
		}

	})
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	organization/1/enable_electronic_voting: true
	user/5:
		username: admin
		organization_management_level: superadmin
	group/40:
		name: delegate
		meeting_id: 1
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1
	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1
	meeting/1/welcome_title: hello world

	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid
	poll/3:
		title: my poll
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: created
		entitled_group_ids: [40]
	`

	withData(t, pg, data, func(service *vote.Vote, flow flow.Flow) {
		t.Run("Update Title", func(t *testing.T) {
			body := `{
				"title": "updated title"
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			poll, err := dsmodels.New(flow).Poll(3).First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}
			if poll.Title != "updated title" {
				t.Fatalf("Expected updated title, got %s", poll.Title)
			}
		})

		t.Run("Update method with same method", func(t *testing.T) {
			body := `{
				"method": "approval",
				"method_config": {
					"allow_abstain": false
				}
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			pollConfig, err := dsmodels.New(flow).PollConfigApproval(77).First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}
			if pollConfig.AllowAbstain {
				t.Fatalf("pollConfigAllowAbstain == true, expected false")
			}
		})

		t.Run("Update method with other method", func(t *testing.T) {
			body := `{
				"method": "selection",
				"method_config": {
					"onehundred_percent_base": "valid"
				}
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			poll, err := dsmodels.New(flow).Poll(3).First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}
			if !strings.HasPrefix(poll.ConfigID, "poll_config_selection") {
				t.Fatalf("Expected method selection, got %s", poll.ConfigID)
			}
		})

		t.Run("Update options", func(t *testing.T) {
			body := `{
				"option_type": "text",
				"options": ["option1", "option2"]
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			ds := dsmodels.New(flow)

			q := ds.Poll(3)
			q = q.Preload(q.OptionList())
			poll, err := q.First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}
			if len(poll.OptionList) != 2 {
				t.Fatalf("Expected two options, got %d", len(poll.OptionList))
			}
		})

		t.Run("Update after start, title", func(t *testing.T) {
			if err := service.Start(t.Context(), 3, 5); err != nil {
				t.Fatalf("Error starting poll: %v", err)
			}

			body := `{
				"title": "new title"
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			poll, err := dsmodels.New(flow).Poll(3).First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}
			if poll.Title != "new title" {
				t.Fatalf("Expected updated title, got %s", poll.Title)
			}
		})

		t.Run("Update after start, method.onehundred_percent_base", func(t *testing.T) {
			if err := service.Start(t.Context(), 3, 5); err != nil {
				t.Fatalf("Error starting poll: %v", err)
			}

			body := `{
				"method_config":{"onehundred_percent_base":"cast"}
			}`

			if err := service.Update(t.Context(), 3, 5, strings.NewReader(body)); err != nil {
				t.Fatalf("Error updating poll: %v", err)
			}

			poll, err := dsmodels.New(flow).Poll(3).First(t.Context())
			if err != nil {
				t.Fatalf("Error getting poll: %v", err)
			}

			configIDRaw, ok := strings.CutPrefix(poll.ConfigID, "poll_config_selection/")
			if !ok {
				t.Fatalf("Expected poll config ID to start with 'poll_config_selection/', got %s", poll.ConfigID)
			}

			configID, err := strconv.Atoi(configIDRaw)
			if err != nil {
				t.Fatalf("Error parsing config ID: %v", err)
			}

			config, err := dsmodels.New(flow).PollConfigSelection(configID).First(t.Context())
			if config.OnehundredPercentBase != "cast" {
				t.Errorf("Expected onehundred_percent_base to be 'cast', got %s", config.OnehundredPercentBase)
			}
		})

		t.Run("Update after start, method.allow_nota", func(t *testing.T) {
			if err := service.Start(t.Context(), 3, 5); err != nil {
				t.Fatalf("Error starting poll: %v", err)
			}

			body := `{
				"method_config":{"allow_nota":true}
			}`

			err := service.Update(t.Context(), 3, 5, strings.NewReader(body))
			if err == nil {
				t.Errorf("Expected invalid config error, got none")
			}
		})
	})
}

func TestManually(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	user/5:
		username: admin
		organization_management_level: superadmin

	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1/welcome_title: hello world
	`

	withData(t, pg, data, func(service *vote.Vote, flow flow.Flow) {
		t.Run("Create", func(t *testing.T) {
			body := `{
				"title": "my poll",
				"content_object_id": "motion/5",
				"method": "approval",
				"method_config": {
					"onehundred_percent_base": "valid"
				},
				"visibility": "manually",
				"meeting_id": 1,
				"result": {"no":"23","yes":"42"}
			}`

			id, err := service.Create(ctx, 5, strings.NewReader(body))
			if err != nil {
				t.Fatalf("Error creating poll: %v", err)
			}

			if id != 1 {
				t.Errorf("Expected id 1, got %d", id)
			}

			poll, err := dsmodels.New(flow).Poll(1).First(ctx)
			if err != nil {
				t.Fatalf("Fetch poll: %v", err)
			}

			if poll.State != "finished" {
				t.Errorf("Poll is in state %s, expected state finished", poll.State)
			}

			if poll.Result != `{"no":"23","yes":"42"}` {
				t.Errorf("Result does not match")
			}
		})

		t.Run("Reset", func(t *testing.T) {
			err := service.Reset(ctx, 1, 5)
			if err != nil {
				t.Fatalf("Error resetting poll: %v", err)
			}

			poll, err := dsmodels.New(flow).Poll(1).First(ctx)
			if err != nil {
				t.Fatalf("Fetch poll: %v", err)
			}

			if poll.State != "finished" {
				t.Errorf("State == %s. A manually poll has to be in state finished after a reset", poll.State)
			}
		})

		t.Run("Invalid json", func(t *testing.T) {
			body := `{
				"result": {THIS IS NOT JSON}
			}`

			err := service.Update(ctx, 1, 5, strings.NewReader(body))

			if err == nil {
				t.Fatalf("Expected an error on invalid json. Got non")
			}

			if !errors.Is(err, vote.ErrInvalid) {
				t.Errorf("Update with invalid json returned an unexpected error: %v", err)
			}
		})
	})
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
				config_id: poll_config_approval/77
				visibility: open
				content_object_id: some_field/1
				sequential_number: 1
				title: myPoll

			poll_config_approval/77:
				allow_abstain: true
				onehundred_percent_base: valid

			meeting/1/id: 1

			user/1:
				is_present_in_meeting_ids: [1]
				meeting_user_ids: [10]
			meeting_user/10:
				user_id: 1
				group_ids: [1]
				meeting_id: 1
			`,
			"1",
		},
		{
			"Weight enabled, user has no weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				config_id: poll_config_approval/77
				visibility: open
				content_object_id: some_field/1
				sequential_number: 1
				title: myPoll

			poll_config_approval/77:
				allow_abstain: true
				onehundred_percent_base: valid

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				meeting_user_ids: [10]
			meeting_user/10:
				user_id: 1
				group_ids: [1]
				meeting_id: 1
			`,
			"1",
		},
		{
			"Weight enabled, user has default weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				config_id: poll_config_approval/77
				visibility: open
				content_object_id: some_field/1
				sequential_number: 1
				title: myPoll

			poll_config_approval/77:
				allow_abstain: true
				onehundred_percent_base: valid

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				meeting_user_ids: [10]
				default_vote_weight: "2.000000"
			meeting_user/10:
				user_id: 1
				group_ids: [1]
				meeting_id: 1
			`,
			"2",
		},
		{
			"Weight enabled, user has default weight and meeting weight",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				config_id: poll_config_approval/77
				visibility: open
				content_object_id: some_field/1
				sequential_number: 1
				title: myPoll

			poll_config_approval/77:
				allow_abstain: true
				onehundred_percent_base: valid

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				meeting_user_ids: [10]
				default_vote_weight: "2.000000"
			meeting_user/10:
				user_id: 1
				group_ids: [1]
				meeting_id: 1
				vote_weight: "3.000000"
			`,
			"3",
		},
		{
			"Weight enabled, user has default weight and meeting weight in other meeting",
			`
			poll/1:
				meeting_id: 1
				entitled_group_ids: [1]
				config_id: poll_config_approval/77
				visibility: open
				content_object_id: some_field/1
				sequential_number: 1
				title: myPoll

			poll_config_approval/77:
				allow_abstain: true
				onehundred_percent_base: valid

			meeting/1/users_enable_vote_weight: true

			user/1:
				is_present_in_meeting_ids: [1]
				meeting_user_ids: [10,11]
				default_vote_weight: "2.000000"
			meeting_user/10:
				user_id: 1
				group_ids: [1]
				meeting_id: 1
			meeting_user/11:
				user_id: 1
				group_ids: [1]
				meeting_id: 2
				vote_weight: "3.000000"
			`,
			"2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ds := dsfetch.New(dsmock.Stub(dsmock.YAMLData(tt.data)))
			weight, err := vote.CalcVoteWeight(t.Context(), ds, 10)
			if err != nil {
				t.Fatalf("CalcVote: %v", err)
			}

			if weight.String() != tt.expectWeight {
				t.Errorf("got weight %q, expected %q", weight, tt.expectWeight)
			}
		})
	}
}

func TestVoteStart(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30]

	user:
		30:
			username: tom
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user/300:
		group_ids: [40]
		user_id: 30
		meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	poll/5:
		title: normal poll
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: created
		entitled_group_ids: [40]


	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Unknown poll", func(t *testing.T) {
				err := service.Start(ctx, 404, 5)
				if !errors.Is(err, vote.ErrNotExists) {
					t.Errorf("Start returned unexpected error: %v", err)
				}
			})

			t.Run("Not started poll", func(t *testing.T) {
				if err := service.Start(ctx, 5, 5); err != nil {
					t.Errorf("Start returned unexpected error: %v", err)
				}
			})

			t.Run("Start poll a second time", func(t *testing.T) {
				if err := service.Start(ctx, 5, 5); err != nil {
					t.Errorf("Start returned unexpected error: %v", err)
				}
			})

			t.Run("Start a finished poll", func(t *testing.T) {
				if err := service.Start(ctx, 5, 5); err != nil {
					t.Fatalf("Start returned unexpected error: %v", err)
				}

				if err := service.Finalize(ctx, 5, 5, false, false); err != nil {
					t.Fatalf("finish poll: %v", err)
				}

				err := service.Start(ctx, 5, 5)
				if !errors.Is(err, vote.ErrInvalid) {
					t.Errorf("Start returned unexpected error: %v", err)
				}
			})
		},
	)
}

func TestFinalize(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30]

	user:
		30:
			username: tom
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user/300:
		group_ids: [40]
		user_id: 30
		meeting_id: 1

	meeting_user/500:
		group_ids: [40]
		user_id: 5
		meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	poll/5:
		title: poll with votes
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: started
		entitled_group_ids: [40]

	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid

	poll_ballot:
		1:
			poll_id: 5
			value: '"yes"'
			poll_ballot_user_id: 10
		2:
			poll_id: 5
			value: '"no"'
			poll_ballot_user_id: 20
	poll_ballot_user:
		10:
			poll_id: 5
			represented_meeting_user_id: 300
			acting_meeting_user_id: 300
		20:
			poll_id: 5
			represented_meeting_user_id: 500
			acting_meeting_user_id: 500
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Unknown poll", func(t *testing.T) {
				err := service.Finalize(ctx, 404, 5, false, false)
				if !errors.Is(err, vote.ErrNotExists) {
					t.Errorf("Stopping an unknown poll has to return an ErrNotExists, got: %v", err)
				}
			})

			t.Run("Poll with votes", func(t *testing.T) {
				if err := service.Finalize(ctx, 5, 5, false, false); err != nil {
					t.Fatalf("Stop returned unexpected error: %v", err)
				}

				poll, err := dsmodels.New(flow).Poll(5).First(ctx)
				if err != nil {
					t.Fatalf("load poll after finalize: %v", err)
				}

				if poll.Result != `{"no":"1","total_ballots":2,"yes":"1"}` {
					t.Errorf("Got result %s, expected %s", poll.Result, `{"no":"1","yes":"1"}`)
				}

				if poll.State != "finished" {
					t.Errorf("Poll state is %s, expected finished", poll.State)
				}
			})

			t.Run("finish poll a second time", func(t *testing.T) {
				if err := service.Finalize(ctx, 5, 5, false, false); err != nil {
					t.Fatalf("Stop returned unexpected error: %v", err)
				}

				poll, err := dsmodels.New(flow).Poll(5).First(ctx)
				if err != nil {
					t.Fatalf("load poll after finalize: %v", err)
				}

				if poll.State != "finished" {
					t.Errorf("Poll state is %s, expected finished", poll.State)
				}
			})

			t.Run("anonymize", func(t *testing.T) {
				if err := service.Finalize(ctx, 5, 5, false, true); err != nil {
					t.Fatalf("Stop returned unexpected error: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(5)
				q = q.Preload(q.BallotList())
				poll, err := q.First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting poll with ballot: %v", err)
				}

				if len(poll.BallotList) == 0 {
					t.Fatalf("poll has no ballots")
				}

				if poll.BallotList[0].Value != `"no"` {
					t.Errorf("first ballots value is %s, expected \"no\"", poll.BallotList[0].Value)
				}

				if !poll.Anonymized {
					t.Errorf("Poll anonymized flag is not set")
				}
			})
		},
	)
}

func TestSaveEntitledUsers(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	meeting/1:
		users_enable_vote_delegations: false
		users_forbid_delegator_to_vote: false
		present_user_ids: [1, 2]

	meeting/2:
		users_enable_vote_delegations: true
		users_forbid_delegator_to_vote: true
		present_user_ids: [1, 2]
		default_group_id: 20
		motions_default_workflow_id: 2
		motions_default_amendment_workflow_id: 2
		committee_id: 1
		reference_projector_id: 2

	meeting/3:
		users_enable_vote_delegations: true
		users_forbid_delegator_to_vote: false
		present_user_ids: [1, 2]
		default_group_id: 30
		motions_default_workflow_id: 3
		motions_default_amendment_workflow_id: 3
		committee_id: 1
		reference_projector_id: 3

	motion_workflow:
		2:
			name: simple
			first_state_id: 200
			meeting_id: 2
		3:
			name: simple
			first_state_id: 300
			meeting_id: 3

	motion_state:
		200:
			name: state
			weight: 1
			workflow_id: 2
			meeting_id: 2
			allow_create_poll: true
			allow_support: true
			set_workflow_timestamp: true
			recommendation_label: state
			css_class: grey
			merge_amendment_into_final: do_not_merge
		300:
			name: state
			weight: 1
			workflow_id: 3
			meeting_id: 3
			allow_create_poll: true
			allow_support: true
			set_workflow_timestamp: true
			recommendation_label: state
			css_class: grey
			merge_amendment_into_final: do_not_merge
	projector:
		2:
			name: p
			meeting_id: 2
			used_as_default_projector_for_agenda_item_list_in_meeting_id: 2
			used_as_default_projector_for_topic_in_meeting_id: 2
			used_as_default_projector_for_list_of_speakers_in_meeting_id: 2
			used_as_default_projector_for_current_los_in_meeting_id: 2
			used_as_default_projector_for_motion_in_meeting_id: 2
			used_as_default_projector_for_amendment_in_meeting_id: 2
			used_as_default_projector_for_motion_block_in_meeting_id: 2
			used_as_default_projector_for_assignment_in_meeting_id: 2
			used_as_default_projector_for_mediafile_in_meeting_id: 2
			used_as_default_projector_for_message_in_meeting_id: 2
			used_as_default_projector_for_countdown_in_meeting_id: 2
			used_as_default_projector_for_assignment_poll_in_meeting_id: 2
			used_as_default_projector_for_motion_poll_in_meeting_id: 2
			used_as_default_projector_for_topic_poll_in_meeting_id: 2
		3:
			name: p
			meeting_id: 3
			used_as_default_projector_for_agenda_item_list_in_meeting_id: 3
			used_as_default_projector_for_topic_in_meeting_id: 3
			used_as_default_projector_for_list_of_speakers_in_meeting_id: 3
			used_as_default_projector_for_current_los_in_meeting_id: 3
			used_as_default_projector_for_motion_in_meeting_id: 3
			used_as_default_projector_for_amendment_in_meeting_id: 3
			used_as_default_projector_for_motion_block_in_meeting_id: 3
			used_as_default_projector_for_assignment_in_meeting_id: 3
			used_as_default_projector_for_mediafile_in_meeting_id: 3
			used_as_default_projector_for_message_in_meeting_id: 3
			used_as_default_projector_for_countdown_in_meeting_id: 3
			used_as_default_projector_for_assignment_poll_in_meeting_id: 3
			used_as_default_projector_for_motion_poll_in_meeting_id: 3
			used_as_default_projector_for_topic_poll_in_meeting_id: 3

	user:
		1:
			username: user_a
		2:
			username: user_b
		3:
			username: user_c
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user:
		11:
			group_ids: [101]
			user_id: 1
			meeting_id: 1
		21:
			group_ids: [101]
			user_id: 2
			meeting_id: 1
		31:
			group_ids: [101]
			user_id: 3
			meeting_id: 1
			vote_delegated_to_ids: [21]
		12:
			group_ids: [102]
			user_id: 1
			meeting_id: 2
		22:
			group_ids: [102]
			user_id: 2
			meeting_id: 2
		32:
			group_ids: [102]
			user_id: 3
			meeting_id: 2
			vote_delegated_to_ids: [22]
		13:
			group_ids: [103]
			user_id: 1
			meeting_id: 3
		23:
			group_ids: [103]
			user_id: 2
			meeting_id: 3
		33:
			group_ids: [103]
			user_id: 3
			meeting_id: 3
			vote_delegated_to_ids: [23]

	group:
		20:
			name: d2
			meeting_id: 2
		30:
			name: d3
			meeting_id: 3
		101:
			name: delegates
			meeting_id: 1
		102:
			name: delegates
			meeting_id: 2
		103:
			name: delegates
			meeting_id: 3

	# Poll 1: Delegation deactivated (Meeting 1)
	poll/1:
		title: No delegation
		meeting_id: 1
		entitled_group_ids: [101]
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/51
		state: started

	# Poll 2: delegation activated, users cannot vote for themselm (Meeting 2)
	poll/2:
		title: No self voting
		meeting_id: 2
		entitled_group_ids: [102]
		config_id: poll_config_approval/78
		visibility: open
		sequential_number: 1
		content_object_id: motion/52
		state: started


	# Poll 3: delegation and self voting activated (Meeting 3)
	poll/3:
		title: self voting allowed
		meeting_id: 3
		entitled_group_ids: [103]
		config_id: poll_config_approval/79
		visibility: open
		sequential_number: 1
		content_object_id: motion/53
		state: started

	poll_config_approval:
		77:
			allow_abstain: true
			onehundred_percent_base: valid
		78:
			allow_abstain: true
			onehundred_percent_base: valid
		79:
			allow_abstain: true
			onehundred_percent_base: valid

	poll_ballot_user:
		1:
			poll_id: 1
			represented_meeting_user_id: 11
			acting_meeting_user_id: 11
		2:
			poll_id: 2
			represented_meeting_user_id: 12
			acting_meeting_user_id: 12
		3:
			poll_id: 3
			represented_meeting_user_id: 13
			acting_meeting_user_id: 13

	motion:
		51:
			meeting_id: 1
			sequential_number: 1
			title: my motion
			state_id: 1
		52:
			meeting_id: 2
			sequential_number: 1
			title: my motion
			state_id: 200
		53:
			meeting_id: 3
			sequential_number: 1
			title: my motion
			state_id: 300

	list_of_speakers:
		71:
			content_object_id: motion/51
			sequential_number: 1
			meeting_id: 1
		72:
			content_object_id: motion/52
			sequential_number: 1
			meeting_id: 2
		73:
			content_object_id: motion/53
			sequential_number: 1
			meeting_id: 3
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Delegation deactivated", func(t *testing.T) {
				if err := service.Finalize(ctx, 1, 5, false, false); err != nil {
					t.Fatalf("Finalize poll 1: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(1)
				q = q.Preload(q.EntitledUserList())
				poll, err := q.First(ctx)
				if err != nil {
					t.Fatalf("Fetch entitled_meeting_user_ids: %v", err)
				}
				var got []int
				for _, entitledUser := range poll.EntitledUserList {
					if id, ok := entitledUser.MeetingUserID.Value(); ok {
						got = append(got, id)
					}
				}
				slices.Sort(got)

				want := []int{11, 21}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %v, want %v", got, want)
				}
			})

			t.Run("no vote for self", func(t *testing.T) {
				if err := service.Finalize(ctx, 2, 5, false, false); err != nil {
					t.Fatalf("Finalize poll 2: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(2)
				q = q.Preload(q.EntitledUserList())
				poll, err := q.First(ctx)
				if err != nil {
					t.Fatalf("Fetch entitled_meeting_user_ids: %v", err)
				}
				var got []int
				for _, entitledUser := range poll.EntitledUserList {
					if id, ok := entitledUser.MeetingUserID.Value(); ok {
						got = append(got, id)
					}
				}
				slices.Sort(got)

				want := []int{12, 32}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %v, want %v", got, want)
				}
			})

			t.Run("vote for self", func(t *testing.T) {
				if err := service.Finalize(ctx, 3, 5, false, false); err != nil {
					t.Fatalf("Finalize poll 3: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(3)
				q = q.Preload(q.EntitledUserList())
				poll, err := q.First(ctx)
				if err != nil {
					t.Fatalf("Fetch entitled_meeting_user_ids: %v", err)
				}
				var got []int
				for _, entitledUser := range poll.EntitledUserList {
					if id, ok := entitledUser.MeetingUserID.Value(); ok {
						got = append(got, id)
					}
				}
				slices.Sort(got)

				want := []int{13, 23, 33}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %v, want %v", got, want)
				}
			})
		},
	)
}

func TestSecretPoll(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30,31]

	user:
		30:
			username: tom
		31:
			username: hans
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user/300:
		group_ids: [40]
		user_id: 30
		meeting_id: 1

	meeting_user/310:
		group_ids: [40]
		user_id: 31
		meeting_id: 1

	meeting_user/500:
		group_ids: [40]
		user_id: 5
		meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	poll/5:
		title: poll with votes
		config_id: poll_config_approval/77
		visibility: secret
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: started
		entitled_group_ids: [40]

	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Vote1", func(t *testing.T) {
				body := `{"value":"Yes"}`
				if err := service.Vote(ctx, 5, 30, strings.NewReader(body)); err != nil {
					t.Fatalf("Error voting for poll: %v", err)
				}

				ds := dsmodels.New(flow)
				ballot, err := ds.PollBallot(1).First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot: %v", err)
				}

				if ballot.Value == `"Yes"` {
					t.Errorf("ballot value was not encrypted")
				}
			})

			t.Run("Vote2", func(t *testing.T) {
				body := `{"value":"Yes"}`
				if err := service.Vote(ctx, 5, 31, strings.NewReader(body)); err != nil {
					t.Fatalf("Error voting for poll: %v", err)
				}

				ds := dsmodels.New(flow)
				ballotList, err := ds.PollBallot(1, 2).Get(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot: %v", err)
				}

				if len(ballotList) != 2 {
					t.Fatalf("Got %d ballots, expted 2", len(ballotList))
				}

				if ballotList[0].Value == ballotList[1].Value {
					t.Errorf("Two ballots with the same value where identical in db")
				}
			})

			t.Run("Finalize", func(t *testing.T) {
				err := service.Finalize(ctx, 5, 5, false, false)
				if err != nil {
					t.Fatalf("Error finalizing poll: %v", err)
				}

				ds := dsmodels.New(flow)
				q := ds.Poll(5)
				q = q.Preload(q.BallotList())
				poll, err := q.First(ctx)
				if err != nil {
					t.Fatalf("Error: Getting poll: %v", err)
				}

				expectResult := `{"total_ballots":2,"yes":"2"}`
				if poll.Result != expectResult {
					t.Errorf("Got result %s, expected %s", poll.Result, expectResult)
				}

				for _, ballot := range poll.BallotList {
					if ballot.Value != `"Yes"` {
						t.Errorf("value of ballot %d was not decrypted", ballot.ID)
					}
				}
			})
		},
	)
}

func TestVoteVote(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30]

	user:
		30:
			username: tom
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user/300:
		group_ids: [40]
		user_id: 30
		meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	poll/5:
		title: poll with votes
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: started
		entitled_group_ids: [40]

	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			t.Run("Poll does not exist in DS", func(t *testing.T) {
				err := service.Vote(ctx, 404, 1, strings.NewReader(`{"value":"Y"}`))
				if !errors.Is(err, vote.ErrNotExists) {
					t.Errorf("Expected ErrNotExists, got: %v", err)
				}
			})

			t.Run("Invalid json", func(t *testing.T) {
				err := service.Vote(ctx, 5, 30, strings.NewReader(`{123`))

				var errTyped vote.TypeError
				if !errors.As(err, &errTyped) {
					t.Fatalf("Vote() did not return an TypeError, got: %v", err)
				}

				if errTyped != vote.ErrInvalid {
					t.Errorf("Got error type `%s`, expected `%s`", errTyped.Type(), vote.ErrInvalid.Type())
				}
			})

			t.Run("Invalid format", func(t *testing.T) {
				err := service.Vote(ctx, 5, 30, strings.NewReader(`{}`))

				if _, ok := errors.AsType[method.InvalidBallotError](err); !ok {
					t.Fatalf("Vote() did not return an TypeError, got: %v", err)
				}
			})

			t.Run("Simple Vote", func(t *testing.T) {
				body := `{"value":"Yes"}`
				if err := service.Vote(ctx, 5, 30, strings.NewReader(body)); err != nil {
					t.Fatalf("Error processing poll: %v", err)
				}

				ds := dsmodels.New(flow)
				ballot, err := ds.PollBallot(1).First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot: %v", err)
				}
				ballotUser, err := ds.PollBallotUser(1).First(t.Context())
				if err != nil {
					t.Fatalf("Error: Getting ballot_user: %v", err)
				}

				if v, ok := ballotUser.ActingMeetingUserID.Value(); ok && v != 300 {
					t.Errorf("Expected acting_meeting_user ID to be 300, got %d", v)
				}

				if ballot.Value != `"Yes"` {
					t.Errorf("Expected vote value to be 'Yes', got '%s'", ballot.Value)
				}
			})

			t.Run("User has voted", func(t *testing.T) {
				err := service.Vote(ctx, 5, 30, strings.NewReader(`{"value":"Yes"}`))
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

				ds := dsmodels.New(flow)
				ballot, err := ds.Poll(5).First(t.Context())

				if len(ballot.BallotIDs) != 1 {
					t.Errorf("Expected 1 ballot ID, got %d", len(ballot.BallotIDs))
				}

				if len(ballot.BallotUserIDs) != 1 {
					t.Errorf("Expected 1 ballot user ID, got %d", len(ballot.BallotUserIDs))
				}
			})

			t.Run("Poll is stopped", func(t *testing.T) {
				if err := service.Finalize(ctx, 5, 5, false, false); err != nil {
					t.Fatalf("Finalize poll: %v", err)
				}

				err := service.Vote(ctx, 5, 30, strings.NewReader(`{"value":"Yes"}`))
				if err == nil {
					t.Fatalf("Vote returned no error")
				}

				var errTyped vote.TypeError
				if !errors.As(err, &errTyped) {
					t.Fatalf("Vote() did not return an TypeError, got: %v", err)
				}

				if errTyped != vote.ErrNotStarted {
					t.Errorf("Got error type `%s`, expected `%s`", errTyped.Type(), vote.ErrNotStarted.Type())
				}

				ds := dsmodels.New(flow)
				ballot, err := ds.Poll(5).First(t.Context())

				if len(ballot.BallotIDs) != 1 {
					t.Errorf("Expected 1 ballot ID, got %d", len(ballot.BallotIDs))
				}

				if len(ballot.BallotUserIDs) != 1 {
					t.Errorf("Expected 1 ballot user ID, got %d", len(ballot.BallotUserIDs))
				}
			})
		},
	)
}

func TestVoteDelegationAndGroup(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	baseData := `
	meeting/1/users_enable_vote_delegations: true

	motion/5:
		meeting_id: 1
		sequential_number: 1
		title: my motion
		state_id: 1

	list_of_speakers/7:
		content_object_id: motion/5
		sequential_number: 1
		meeting_id: 1

	group/40:
		name: delegates
		meeting_id: 1

	group/41:
		name: some_group
		meeting_id: 1

	user:
		5:
			username: admin
			organization_management_level: superadmin
		30:
			username: tom

		40:
			username: georg

	meeting_user:
		31:
			user_id: 30
			meeting_id: 1
			group_ids: [41]

		41:
			user_id: 40
			meeting_id: 1
			group_ids: [41]

	poll_config_approval/77:
		allow_abstain: true
		onehundred_percent_base: valid

	poll/5:
		title: normal poll
		config_id: poll_config_approval/77
		visibility: open
		sequential_number: 1
		content_object_id: motion/5
		meeting_id: 1
		state: started
		entitled_group_ids: [40]
	`

	for _, tt := range []struct {
		name string
		data string
		vote string

		expectRepresentedMeetingUserID int
	}{
		{
			"Not delegated",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
			`,
			`{"value":"Yes"}`,

			31,
		},

		{
			"Not delegated not present",
			`
			meeting_user/31:
				group_ids: [40]
			`,
			`{"value":"Yes"}`,

			0,
		},

		{
			"Not delegated not in group",
			`
			user/30:
				is_present_in_meeting_ids: [1]
			`,
			`{"value":"Yes"}`,

			0,
		},

		{
			"Vote for self",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
			`,
			`{"meeting_user_id": 31, "value":"Yes"}`,

			31,
		},

		{
			"Vote for self not activated",
			`
			meeting/1/users_enable_vote_delegations: false
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
			`,
			`{"meeting_user_id": 31, "value":"Yes"}`,

			31,
		},

		{
			"Vote for anonymous",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
			`,
			`{"meeting_user_id": 0, "value":"Yes"}`,

			0,
		},

		{
			"Vote for other without delegation",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
			`,
			`{"meeting_user_id": 41, "value":"Yes"}`,

			0,
		},

		{
			"Vote for other with delegation",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user:
				41:
					group_ids: [40]
					vote_delegated_to_ids: [31]
			`,
			`{"meeting_user_id": 41, "value":"Yes"}`,

			41,
		},

		{
			"Vote for other with delegation not activated",
			`
			meeting/1/users_enable_vote_delegations: false
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user:
				41:
					group_ids: [40]
					vote_delegated_to_ids: [31]
			`,
			`{"meeting_user_id": 41, "value":"Yes"}`,

			0,
		},

		{
			"Vote for other with delegation not in group",
			`
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user:
				41:
					vote_delegated_to_ids: [31]
			`,
			`{"meeting_user_id": 41, "value":"Yes"}`,

			0,
		},

		{
			"Vote for self when delegation is activated users_forbid_delegator_to_vote==false",
			`
			meeting/1/users_forbid_delegator_to_vote: false
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
				vote_delegated_to_ids: [41]
			`,
			`{"meeting_user_id": 31, "value":"Yes"}`,

			31,
		},

		{
			"Vote for self when delegation is activated users_forbid_delegator_to_vote==true",
			`
			meeting/1/users_forbid_delegator_to_vote: true
			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
				vote_delegated_to_ids: [41]
			`,
			`{"meeting_user_id": 31, "value":"Yes"}`,

			0,
		},

		{
			"Vote for self when delegation is deactivated users_forbid_delegator_to_vote==true",
			`
			meeting/1:
				users_forbid_delegator_to_vote: true
				users_enable_vote_delegations: false

			user/30:
				is_present_in_meeting_ids: [1]

			meeting_user/31:
				group_ids: [40]
				vote_delegated_to_ids: [41]
			`,
			`{"meeting_user_id": 31, "value":"Yes"}`,

			31,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			pg, err := pgtest.NewPostgresTest(t)
			if err != nil {
				t.Fatalf("Error starting postgres: %v", err)
			}

			if err := pg.AddData(ctx, baseData); err != nil {
				t.Fatalf("Insert base data: %v", err)
			}

			withData(
				t,
				pg,
				tt.data,
				func(service *vote.Vote, flow flow.Flow) {
					err := service.Vote(ctx, 5, 30, strings.NewReader(tt.vote))

					if tt.expectRepresentedMeetingUserID != 0 {
						if err != nil {
							t.Fatalf("Vote returned unexpected error: %v", err)
						}

						ds := dsmodels.New(flow)
						q := ds.Poll(5)
						q = q.Preload(q.BallotUserList())
						poll, err := q.First(ctx)
						if err != nil {
							t.Fatalf("Error: Getting votes from poll: %v", err)
						}
						found := slices.ContainsFunc(poll.BallotUserList, func(ballotUser dsmodels.PollBallotUser) bool {
							v, ok := ballotUser.RepresentedMeetingUserID.Value()
							return ok && v == tt.expectRepresentedMeetingUserID
						})

						if !found {
							t.Errorf("user %d has not voted", tt.expectRepresentedMeetingUserID)
						}

						return
					}

					if !errors.Is(err, vote.ErrNotAllowed) {
						t.Fatalf("Expected NotAllowedError, got: %v", err)
					}
				},
			)
		})
	}
}

func TestDeleteWithOtherCollections(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("Postgres Test")
	}

	ctx := t.Context()

	pg, err := pgtest.NewPostgresTest(t)
	if err != nil {
		t.Fatalf("Error starting postgres: %v", err)
	}

	data := `---
	assignment/5:
		meeting_id: 1
		sequential_number: 1
		title: my assignment

	list_of_speakers/7:
		content_object_id: assignment/5
		sequential_number: 1
		meeting_id: 1

	meeting/1:
		present_user_ids: [30]

	user:
		30:
			username: tom
		5:
			username: admin
			organization_management_level: superadmin

	meeting_user:
		300:
			group_ids: [40]
			user_id: 30
			meeting_id: 1
		50:
			group_ids: [40]
			user_id: 5
			meeting_id: 1

	group/40:
		name: delegate
		meeting_id: 1

	poll/5:
		title: poll with votes and options
		config_id: poll_config_selection/77
		visibility: open
		sequential_number: 1
		content_object_id: assignment/5
		meeting_id: 1
		state: started
		entitled_group_ids: [40]

	poll_config_selection/77:
		onehundred_percent_base: valid

	poll_option/31:
		poll_id: 5
		content_object_id: user/30

	poll_ballot:
		501:
			poll_id: 5
			value: Yes
		502:
			poll_id: 5
			value: No

	poll_ballot_user:
		5010:
			poll_id: 5
			acting_meeting_user_id: 300
			represented_meeting_user_id: 300
		5020:
			poll_id: 5
			acting_meeting_user_id: 50
			represented_meeting_user_id: 50

	projection/33:
		content_object_id: poll/5
		meeting_id: 1
	`

	withData(
		t,
		pg,
		data,
		func(service *vote.Vote, flow flow.Flow) {
			err := service.Delete(ctx, 5, 5)
			if err != nil {
				t.Errorf("Error: %v", err)
			}
		},
	)
}

func withData(t *testing.T, pg *pgtest.PostgresTest, data string, fn func(service *vote.Vote, flow flow.Flow)) {
	t.Helper()

	ctx := t.Context()

	if err := pg.AddData(ctx, data); err != nil {
		t.Fatalf("Error: inserting data: %v", err)
	}

	flow, err := pg.Flow(ctx)
	if err != nil {
		t.Fatalf("Error getting flow: %v", err)
	}
	defer flow.Close()

	conn, err := pg.Conn(ctx)
	if err != nil {
		t.Fatalf("Error getting connection: %v", err)
	}
	defer conn.Close(ctx)

	service, _, err := vote.New(environment.ForTests{}, flow, conn)
	if err != nil {
		t.Fatalf("Error creating vote: %v", err)
	}

	fn(service, flow)
}
