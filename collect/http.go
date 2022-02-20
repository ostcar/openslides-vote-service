package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

const (
	httpPathInternal = "/internal/vote"
	httpPathExternal = "/system/vote"
)

// Authenticater is used to find out the user id for a request
type Authenticater interface {
	Authenticate(http.ResponseWriter, *http.Request) (context.Context, error)
	FromContext(context.Context) int
}

// RegisterHandler adds all handlers to a http.ServeMux
func RegisterHandler(mux *http.ServeMux, service *Vote, auth Authenticater) {
	handleStart(mux, service)
	handleStop(mux, service)
	handleClear(mux, service)
	handleClearAll(mux, service)
	handleVote(mux, service, auth)
	handleVoted(mux, service, auth)
	handleVoteCount(mux, service)
	handleHealth(mux)
}

type starter interface {
	Start(ctx context.Context, pollID int) ([]byte, []byte, error)
}

func handleStart(mux *http.ServeMux, start starter) {
	mux.HandleFunc(
		// TODO: change this to start. "create" is only used 4.0
		httpPathInternal+"/create",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive start request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "POST" {
				http.Error(w, MessageError{ErrInvalid, "Only POST requests are allowed"}.Error(), 405)
				return
			}

			id, err := pollID(r)
			if err != nil {
				http.Error(w, MessageError{ErrInvalid, err.Error()}.Error(), 400)
				return
			}

			pubkey, pubKeySig, err := start.Start(r.Context(), id)
			if err != nil {
				handleError(w, err, true)
				return
			}

			content := struct {
				PubKey    []byte `json:"public_key"`
				PubKeySig []byte `json:"public_key_sig"`
			}{
				pubkey,
				pubKeySig,
			}
			if err := json.NewEncoder(w).Encode(content); err != nil {
				http.Error(w, MessageError{ErrInternal, err.Error()}.Error(), 500)
				return
			}
		},
	)
}

// stopper stops a poll. It sets the state of the poll, so that no other user
// can vote. It writes the vote results to the writer.
type stopper interface {
	Stop(ctx context.Context, pollID int, w io.Writer) error
}

func handleStop(mux *http.ServeMux, stop stopper) {
	mux.HandleFunc(
		httpPathInternal+"/stop",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive stop request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "POST" {
				http.Error(w, MessageError{ErrInvalid, "Only POST requests are allowed"}.Error(), 405)
				return
			}

			id, err := pollID(r)
			if err != nil {
				http.Error(w, MessageError{ErrInvalid, err.Error()}.Error(), 400)
				return
			}

			// TODO: Remove buf and convert4_0
			buf := new(bytes.Buffer)

			if err := stop.Stop(r.Context(), id, buf); err != nil {
				handleError(w, err, true)
				return
			}

			fmt.Printf("\n\n\n")
			fmt.Println("Original:", buf.String())
			fmt.Printf("\n\n\n")
			if err := convert4_0(w, buf); err != nil {
				handleError(w, err, true)
				return
			}
		},
	)
}

func convert4_0(w io.Writer, r io.Reader) error {
	var newContent struct {
		Votes struct {
			Votes []json.RawMessage `json:"votes"`
		} `json:"votes"`
		Signature []byte `json:"signature"`
		Users     []int  `json:"user_ids"`
	}

	if err := json.NewDecoder(r).Decode(&newContent); err != nil {
		return fmt.Errorf("decoding content: %w", err)
	}

	oldVotes := make([]json.RawMessage, len(newContent.Votes.Votes))
	for i, vote := range newContent.Votes.Votes {
		oldVote := struct {
			RequestUser int             `json:"request_user_id,omitempty"`
			VoteUser    int             `json:"vote_user_id,omitempty"`
			Value       json.RawMessage `json:"value"`
			Weight      string          `json:"weight"`
		}{
			0,
			0,
			vote,
			"1.000000",
		}
		bs, err := json.Marshal(oldVote)
		if err != nil {
			return fmt.Errorf("decoding old vote %d: %v", i, err)
		}

		oldVotes[i] = bs
	}

	oldContent := struct {
		Votes []json.RawMessage `json:"votes"`
		Users []int             `json:"user_ids"`
	}{
		oldVotes,
		newContent.Users,
	}

	if err := json.NewEncoder(w).Encode(oldContent); err != nil {
		return fmt.Errorf("encoding content: %w", err)
	}

	return nil
}

type clearer interface {
	Clear(ctx context.Context, pollID int) error
}

func handleClear(mux *http.ServeMux, clear clearer) {
	mux.HandleFunc(
		httpPathInternal+"/clear",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive clear request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "POST" {
				http.Error(w, MessageError{ErrInvalid, "Only POST requests are allowed"}.Error(), 405)
				return
			}

			id, err := pollID(r)
			if err != nil {
				http.Error(w, MessageError{ErrInvalid, err.Error()}.Error(), 400)
				return
			}

			if err := clear.Clear(r.Context(), id); err != nil {
				handleError(w, err, true)
				return
			}
		},
	)
}

type clearAller interface {
	ClearAll(ctx context.Context) error
}

func handleClearAll(mux *http.ServeMux, clear clearAller) {
	mux.HandleFunc(
		httpPathInternal+"/clear_all",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive clear request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "POST" {
				http.Error(w, MessageError{ErrInvalid, "Only POST requests are allowed"}.Error(), 405)
				return
			}

			if err := clear.ClearAll(r.Context()); err != nil {
				handleError(w, err, true)
				return
			}
		},
	)
}

type voter interface {
	Vote(ctx context.Context, pollID, requestUser int, r io.Reader) error
}

func handleVote(mux *http.ServeMux, vote voter, auth Authenticater) {
	mux.HandleFunc(
		httpPathExternal,
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive vote request")
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "POST" {
				http.Error(w, MessageError{ErrInvalid, "Only POST requests are allowed"}.Error(), 405)
				return
			}

			ctx, err := auth.Authenticate(w, r)
			if err != nil {
				handleError(w, err, false)
				return
			}

			uid := auth.FromContext(ctx)
			if uid == 0 {
				http.Error(w, MessageError{ErrNotAllowed, "Anonymous user can not vote"}.Error(), 401)
				return
			}

			id, err := pollID(r)
			if err != nil {
				http.Error(w, MessageError{ErrInvalid, err.Error()}.Error(), 400)
				return
			}

			if err := vote.Vote(ctx, id, uid, r.Body); err != nil {
				handleError(w, err, false)
				return
			}
		},
	)
}

type votedPollser interface {
	VotedPolls(ctx context.Context, pollIDs []int, requestUser int, w io.Writer) error
}

func handleVoted(mux *http.ServeMux, voted votedPollser, auth Authenticater) {
	mux.HandleFunc(
		httpPathExternal+"/voted",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive voted request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			if r.Method != "GET" {
				http.Error(w, MessageError{ErrInvalid, "Only GET requests are allowed"}.Error(), 405)
				return
			}

			ctx, err := auth.Authenticate(w, r)
			if err != nil {
				handleError(w, err, false)
				return
			}

			uid := auth.FromContext(ctx)
			if uid == 0 {
				http.Error(w, MessageError{ErrNotAllowed, "Anonymous user can not vote"}.Error(), 401)
				return
			}

			pollIDs, err := pollsID(r)
			if err != nil {
				http.Error(w, MessageError{ErrInvalid, err.Error()}.Error(), 400)
				return
			}

			if err := voted.VotedPolls(ctx, pollIDs, uid, w); err != nil {
				handleError(w, err, false)
				return
			}
		},
	)
}

type voteCounter interface {
	VoteCount(ctx context.Context, id uint64, blocking bool, w io.Writer) error
}

func handleVoteCount(mux *http.ServeMux, voteCounter voteCounter) {
	mux.HandleFunc(
		httpPathInternal+"/vote_count",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receive vote count request: %v", r)
			w.Header().Set("Content-Type", "application/json")

			rawID := r.URL.Query().Get("id")
			var id uint64
			blocking := false
			if rawID != "" {
				blocking = true
				var err error
				id, err = strconv.ParseUint(rawID, 10, 64)
				if err != nil {
					handleError(w, fmt.Errorf("parsing id: %w", err), true)
					return
				}

			}

			if err := voteCounter.VoteCount(r.Context(), id, blocking, w); err != nil {
				handleError(w, err, true)
				return
			}

		},
	)
}

func handleHealth(mux *http.ServeMux) {
	mux.HandleFunc(
		httpPathExternal+"/health",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			fmt.Fprintf(w, `{"health":true}`)
		},
	)
}

func pollID(r *http.Request) (int, error) {
	rawID := r.URL.Query().Get("id")
	if rawID == "" {
		return 0, fmt.Errorf("no id argument provided")
	}

	id, err := strconv.Atoi(rawID)
	if err != nil {
		return 0, fmt.Errorf("id invalid. Expected int, got %s", rawID)
	}

	return id, nil
}

func pollsID(r *http.Request) ([]int, error) {
	rawIDs := strings.Split(r.URL.Query().Get("ids"), ",")

	ids := make([]int, len(rawIDs))
	for i, rawID := range rawIDs {
		id, err := strconv.Atoi(rawID)
		if err != nil {
			return nil, fmt.Errorf("%dth id invalid. Expected int, got %s", i, rawID)
		}
		ids[i] = id
	}

	return ids, nil
}

func handleError(w http.ResponseWriter, err error, internal bool) {
	status := 400
	var msg string

	var errTyped interface {
		error
		Type() string
	}
	if errors.As(err, &errTyped) {
		msg = errTyped.Error()
	} else {
		// Unknown error. Handle as 500er
		status = 500
		msg = ErrInternal.Error()
		if internal {
			msg = MessageError{ErrInternal, err.Error()}.Error()
		}
		log.Info("Error: %v", err)
	}
	log.Debug("HTTP: Returning status %d", status)

	w.WriteHeader(status)
	fmt.Fprint(w, msg)
}
