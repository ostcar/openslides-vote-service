package vote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

type starterStub struct {
	id        int
	expectErr error
}

func (c *starterStub) Start(ctx context.Context, pollID int) ([]byte, []byte, error) {
	c.id = pollID
	return nil, nil, c.expectErr
}

func TestHandleStart(t *testing.T) {
	starter := &starterStub{}

	url := "/internal/vote/start"
	mux := http.NewServeMux()
	handleStart(mux, starter)

	t.Run("Get request", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("No id", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400 - Bad Request", resp.Result().Status)
		}
	})

	t.Run("Invalid id", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=value", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400 - Bad Request", resp.Result().Status)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", strings.NewReader("request body")))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
		}

		if starter.id != 1 {
			t.Errorf("Start was called with id %d, expected 1", starter.id)
		}
	})

	t.Run("Exist error", func(t *testing.T) {
		starter.expectErr = ErrExists

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", strings.NewReader("request body")))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "exist" {
			t.Errorf("Got error `%s`, expected `exist`", body.Error)
		}
	})

	t.Run("Internal error", func(t *testing.T) {
		starter.expectErr = errors.New("TEST_Error")

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", strings.NewReader("request body")))

		if resp.Result().StatusCode != 500 {
			t.Errorf("Got status %s, expected 500", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
			MSG   string `json:"message"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "internal" {
			t.Errorf("Got error `%s`, expected `internal`", body.Error)
		}

		if body.MSG != "TEST_Error" {
			t.Errorf("Got error message `%s`, expected `TEST_Error`", body.MSG)
		}
	})
}

type stopperStub struct {
	id        int
	expectErr error

	expectVotes       json.RawMessage
	expectedSignature []byte
	expectedUserIDs   []int
}

func (s *stopperStub) Stop(ctx context.Context, pollID int) (json.RawMessage, []byte, []int, error) {
	s.id = pollID

	if s.expectErr != nil {
		return nil, nil, nil, s.expectErr
	}

	return s.expectVotes, s.expectedSignature, s.expectedUserIDs, nil
}

func TestHandleStop(t *testing.T) {
	stopper := &stopperStub{}

	url := "/internal/vote/stop"
	mux := http.NewServeMux()
	handleStop(mux, stopper)

	t.Run("Get request", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("No id", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400 - Bad Request", resp.Result().Status)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		stopper.expectVotes = []byte(`"some values"`)

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
		}

		if stopper.id != 1 {
			t.Errorf("Stopper was called with id %d, expected 1", stopper.id)
		}

		expect := `{"votes":"some values","signature":null,"user_ids":[]}`
		if trimed := strings.TrimSpace(resp.Body.String()); trimed != expect {
			t.Errorf("Got body `%s`, expected `%s`", trimed, expect)
		}
	})

	t.Run("Not Exist error", func(t *testing.T) {
		stopper.expectErr = ErrNotExists

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-exist" {
			t.Errorf("Got error `%s`, expected `not-exist`", body.Error)
		}
	})
}

type clearerStub struct {
	id        int
	expectErr error
}

func (c *clearerStub) Clear(ctx context.Context, pollID int) error {
	c.id = pollID
	return c.expectErr
}

func TestHandleClear(t *testing.T) {
	clearer := &clearerStub{}

	url := "/internal/vote/clear"
	mux := http.NewServeMux()
	handleClear(mux, clearer)

	t.Run("Get request", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("No id", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400 - Bad Request", resp.Result().Status)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
		}

		if clearer.id != 1 {
			t.Errorf("Clearer was called with id %d, expected 1", clearer.id)
		}
	})

	t.Run("Not Exist error", func(t *testing.T) {
		clearer.expectErr = ErrNotExists

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-exist" {
			t.Errorf("Got error `%s`, expected `not-exist`", body.Error)
		}
	})
}

type clearAllerStub struct {
	expectErr error
}

func (c *clearAllerStub) ClearAll(ctx context.Context) error {
	return c.expectErr
}

func TestHandleClearAll(t *testing.T) {
	clearAller := &clearAllerStub{}

	url := "/internal/vote/clear_all"
	mux := http.NewServeMux()
	handleClearAll(mux, clearAller)

	t.Run("Get request", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
		}
	})

	t.Run("Not Exist error", func(t *testing.T) {
		clearAller.expectErr = ErrNotExists

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-exist" {
			t.Errorf("Got error `%s`, expected `not-exist`", body.Error)
		}
	})
}

type voterStub struct {
	id        int
	user      int
	body      string
	expectErr error
}

func (v *voterStub) Vote(ctx context.Context, pollID, requestUser int, r io.Reader) error {
	v.id = pollID
	v.user = requestUser

	body, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	v.body = string(body)
	return v.expectErr
}

type AuthError struct{}

func (AuthError) Error() string {
	return `{"error":"auth","message":"auth error"}`
}

func (AuthError) Type() string {
	return "auth"
}

type autherStub struct {
	userID  int
	authErr bool
}

func (a *autherStub) Authenticate(w http.ResponseWriter, r *http.Request) (context.Context, error) {
	if a.authErr {
		return nil, AuthError{}
	}
	return r.Context(), nil
}

func (a *autherStub) FromContext(context.Context) int {
	return a.userID
}

func TestHandleVote(t *testing.T) {
	voter := &voterStub{}
	auther := &autherStub{}

	url := "/system/vote"
	mux := http.NewServeMux()
	handleVote(mux, voter, auther)

	t.Run("Get request", func(t *testing.T) {
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("No id", func(t *testing.T) {
		auther.userID = 5

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400 - Bad Request", resp.Result().Status)
		}
	})

	t.Run("ErrDoubleVote error", func(t *testing.T) {
		voter.expectErr = ErrDoubleVote

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "douple-vote" {
			t.Errorf("Got error `%s`, expected `douple-vote`", body.Error)
		}
	})

	t.Run("Auth error", func(t *testing.T) {
		auther.authErr = true

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "auth" {
			t.Errorf("Got error `%s`, expected `auth`", body.Error)
		}
	})

	t.Run("Anonymous", func(t *testing.T) {
		auther.userID = 0
		auther.authErr = false

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", nil))

		if resp.Result().StatusCode != 401 {
			t.Errorf("Got status %s, expected 401", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-allowed" {
			t.Errorf("Got error `%s`, expected `auth`", body.Error)
		}
	})

	t.Run("Valid", func(t *testing.T) {
		auther.userID = 5
		voter.body = "request body"
		voter.expectErr = nil

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url+"?id=1", strings.NewReader("request body")))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
		}

		if voter.id != 1 {
			t.Errorf("Voter was called with id %d, expected 1", voter.id)
		}

		if voter.user != 5 {
			t.Errorf("Voter was called with userID %d, expected 5", voter.user)
		}

		if voter.body != "request body" {
			t.Errorf("Voter was called with body `%s` expected `request body`", voter.body)
		}
	})
}

type votedPollserStub struct {
	pollIDs      []int
	user         int
	expectWriter string
	expectErr    error
}

func (v *votedPollserStub) VotedPolls(ctx context.Context, pollIDs []int, requestUser int, w io.Writer) error {
	v.pollIDs = pollIDs
	v.user = requestUser

	if v.expectErr != nil {
		return v.expectErr
	}
	_, err := w.Write([]byte(v.expectWriter))
	return err
}

func TestHandleVoted(t *testing.T) {
	voted := &votedPollserStub{}
	auther := &autherStub{}

	url := "/system/vote/voted"
	mux := http.NewServeMux()
	handleVoted(mux, voted, auther)

	t.Run("POST request", func(t *testing.T) {
		auther.userID = 5
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("POST", url, nil))

		if resp.Result().StatusCode != 405 {
			t.Errorf("Got status %s, expected 405 - Method not allowed", resp.Result().Status)
		}
	})

	t.Run("No polls given", func(t *testing.T) {
		auther.userID = 5
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}
	})

	t.Run("Wrong polls value", func(t *testing.T) {
		auther.userID = 5
		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url+"?ids=foo", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}
	})

	t.Run("Auth error", func(t *testing.T) {
		auther.authErr = true

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url+"?ids=1", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "auth" {
			t.Errorf("Got error `%s`, expected `auth`", body.Error)
		}
	})

	t.Run("Anonymous", func(t *testing.T) {
		auther.authErr = false
		auther.userID = 0

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url+"?ids=1", nil))

		if resp.Result().StatusCode != 401 {
			t.Errorf("Got status %s, expected 401", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-allowed" {
			t.Errorf("Got error `%s`, expected `not-allowed`", body.Error)
		}
	})

	t.Run("Correct", func(t *testing.T) {
		auther.userID = 5
		auther.authErr = false

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url+"?ids=1,2", nil))

		if resp.Result().StatusCode != 200 {
			t.Errorf("Got status %s, expected 200", resp.Result().Status)
		}

		if len(voted.pollIDs) != 2 || voted.pollIDs[0] != 1 || voted.pollIDs[1] != 2 {
			t.Errorf("Voted was called with pollIDs %v, expected [1,2]", voted.pollIDs)
		}
	})

	t.Run("Voted Error", func(t *testing.T) {
		auther.userID = 5
		auther.authErr = false
		voted.expectErr = ErrNotExists

		resp := httptest.NewRecorder()
		mux.ServeHTTP(resp, httptest.NewRequest("GET", url+"?ids=1,2", nil))

		if resp.Result().StatusCode != 400 {
			t.Errorf("Got status %s, expected 400", resp.Result().Status)
		}

		var body struct {
			Error string `json:"error"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decoding resp body: %v", err)
		}

		if body.Error != "not-exist" {
			t.Errorf("Got error `%s`, expected `not-exist`", body.Error)
		}
	})
}

type voteCounterStub struct {
	expectCount map[int]int
	expectErr   error
}

func (v *voteCounterStub) VoteCount(ctx context.Context) (map[int]int, error) {
	return v.expectCount, v.expectErr
}

func TestHandleVoteCountFirstData(t *testing.T) {
	voteCounter := &voteCounterStub{}

	eventer := func() (<-chan time.Time, func()) {
		return make(chan time.Time), func() {}
	}

	mux := http.NewServeMux()
	handleVoteCount(mux, voteCounter, eventer)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	url := "/internal/vote/vote_count"
	resp := httptest.NewRecorder()
	voteCounter.expectCount = map[int]int{1: 10, 2: 20}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	mux.ServeHTTP(resp, req)

	if resp.Result().StatusCode != 200 {
		t.Fatalf("Got status %s, expected 200", resp.Result().Status)
	}

	var got map[int]int
	if err := json.NewDecoder(resp.Result().Body).Decode(&got); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if !reflect.DeepEqual(got, voteCounter.expectCount) {
		t.Errorf("Got %v, expected %v", got, voteCounter.expectCount)
	}
}

func TestHandleVoteCountFirstDataEmpty(t *testing.T) {
	voteCounter := &voteCounterStub{}

	eventer := func() (<-chan time.Time, func()) {
		return make(chan time.Time), func() {}
	}

	mux := http.NewServeMux()
	handleVoteCount(mux, voteCounter, eventer)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	url := "/internal/vote/vote_count"
	resp := httptest.NewRecorder()
	voteCounter.expectCount = map[int]int{}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	mux.ServeHTTP(resp, req)

	if resp.Result().StatusCode != 200 {
		t.Fatalf("Got status %s, expected 200", resp.Result().Status)
	}

	var got map[int]int
	if err := json.NewDecoder(resp.Result().Body).Decode(&got); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if !reflect.DeepEqual(got, voteCounter.expectCount) {
		t.Errorf("Got %v, expected %v", got, voteCounter.expectCount)
	}
}

func TestHandleVoteCountSecondData(t *testing.T) {
	voteCounter := &voteCounterStub{}

	event := make(chan time.Time, 1)
	eventer := func() (<-chan time.Time, func()) {
		return event, func() {}
	}

	mux := http.NewServeMux()
	handleVoteCount(mux, voteCounter, eventer)

	ctx := context.Background()

	data := []map[int]int{
		{1: 10, 2: 20},
		{1: 11, 2: 20}, // Change only 1
		{1: 11, 2: 20}, // No Change
		{1: 11},        // Remove 2
		{1: 11, 3: 30}, // Add 3
	}

	url := "/internal/vote/vote_count"
	resp := httptest.NewRecorder()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)

	voteCounter.expectCount = data[0]
	i := 0
	flushResp := onFlush{resp, func() {
		i++
		if i >= len(data) {
			close(event)
			return
		}
		voteCounter.expectCount = data[i]
		event <- time.Now()
	}}

	mux.ServeHTTP(flushResp, req)

	if resp.Result().StatusCode != 200 {
		t.Fatalf("Got status %s, expected 200", resp.Result().Status)
	}

	expect := []map[int]int{
		{1: 10, 2: 20},
		{1: 11},
		{2: 0},
		{3: 30},
	}

	decoder := json.NewDecoder(resp.Body)
	for i := range expect {
		var got map[int]int
		if err := decoder.Decode(&got); err != nil {
			if err == io.EOF {
				t.Errorf("Got %d packages, expected %d", i, len(expect))
				break
			}
			t.Fatalf("decoding: %v", err)
		}

		if !reflect.DeepEqual(got, expect[i]) {
			t.Errorf("Data %d: Got %v, expected %v", i+1, got, expect[i])
		}
	}
}

func TestHandleHealth(t *testing.T) {
	url := "/system/vote/health"
	mux := http.NewServeMux()
	handleHealth(mux)

	resp := httptest.NewRecorder()
	mux.ServeHTTP(resp, httptest.NewRequest("GET", url, nil))

	if resp.Result().StatusCode != 200 {
		t.Errorf("Got status %s, expected 200 - OK", resp.Result().Status)
	}

	expect := `{"healthy":true}`
	if got := resp.Body.String(); got != expect {
		t.Errorf("Got body `%s`, expected `%s`", got, expect)
	}
}

type onFlush struct {
	http.ResponseWriter
	f func()
}

func (f onFlush) Flush() {
	f.f()
	if flusher, ok := f.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
