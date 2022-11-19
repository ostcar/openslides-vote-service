package vote

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsfetch"
	"github.com/OpenSlides/openslides-autoupdate-service/pkg/datastore/dsmock"
)

func TestPreload(t *testing.T) {
	for _, tt := range []struct {
		name        string
		data        string
		expectCount int
	}{
		{
			"one user",
			`---
			meeting/5/id: 5
			poll/1:
				meeting_id: 5
				entitled_group_ids: [30]
				pollmethod: Y
				global_yes: true
				backend: fast
				type: pseudoanonymous

			group/30/user_ids: [50]

			user:
				50:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [31]
					is_present_in_meeting: [5]
			`,
			2,
		},

		{
			"Many groups",
			`---
			meeting/5/id: 5
			poll/1:
				meeting_id: 5
				entitled_group_ids: [30,31]
				pollmethod: Y
				global_yes: true
				backend: fast
				type: pseudoanonymous

			group/30/user_ids: [50]
			group/31/user_ids: [50]

			user:
				50:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]
			`,
			2,
		},

		{
			"Many users",
			`---
			meeting/5/id: 5
			poll/1:
				meeting_id: 5
				entitled_group_ids: [30]
				pollmethod: Y
				global_yes: true
				backend: fast
				type: pseudoanonymous

			group/30/user_ids: [50,51]

			user:
				50:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]

				51:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]
			`,
			2,
		},

		{
			"Many users in different groups",
			`---
			meeting/5/id: 5
			poll/1:
				meeting_id: 5
				entitled_group_ids: [30, 31]
				pollmethod: Y
				global_yes: true
				backend: fast
				type: pseudoanonymous

			group/30/user_ids: [50]
			group/31/user_ids: [51]

			user:
				50:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]

				51:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]
			`,
			2,
		},

		{
			"Many users in different groups with delegation",
			`---
			meeting/5/id: 5
			poll/1:
				meeting_id: 5
				entitled_group_ids: [30, 31]
				pollmethod: Y
				global_yes: true
				backend: fast
				type: pseudoanonymous

			group/30/user_ids: [50]
			group/31/user_ids: [51]

			user:
				50:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]
					vote_delegated_$5_to_id: 52

				51:
					is_present_in_meeting_ids: [5]
					group_$5_ids: [30]
					is_present_in_meeting: [5]
					vote_delegated_$5_to_id: 53

				52:
					is_present_in_meeting_ids: [5]

				53:
					is_present_in_meeting_ids: [5]
			`,
			3,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dsCount := dsmock.NewCounter(dsmock.Stub(dsmock.YAMLData(tt.data)))
			ds := dsmock.NewCache(dsCount)

			poll, err := loadPoll(context.Background(), dsfetch.New(ds), 1)
			if err != nil {
				t.Fatalf("loadPoll returned: %v", err)
			}

			dsCount.(*dsmock.Counter).Reset()
			poll.preload(context.Background(), dsfetch.New(ds))

			if err != nil {
				t.Errorf("preload returned: %v", err)
			}

			if got := dsCount.(*dsmock.Counter).Value(); got != tt.expectCount {
				buf := new(bytes.Buffer)
				for _, req := range dsCount.(*dsmock.Counter).Requests() {
					fmt.Fprintln(buf, req)
				}
				t.Errorf("preload send %d requests, expected %d:\n%s", got, tt.expectCount, buf)
			}
		})
	}
}
