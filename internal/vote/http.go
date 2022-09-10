package vote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSlides/openslides-vote-service/internal/log"
)

const (
	httpPathInternal = "/internal/vote"
	httpPathExternal = "/system/vote"
)

type starter interface {
	Start(ctx context.Context, pollID int) ([]byte, []byte, error)
}

func handleStart(mux *http.ServeMux, start starter) {
	mux.HandleFunc(
		httpPathInternal+"/start",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving start request")
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
	Stop(ctx context.Context, pollID int) (json.RawMessage, []byte, []int, error)
}

func handleStop(mux *http.ServeMux, stop stopper) {
	mux.HandleFunc(
		httpPathInternal+"/stop",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving stop request")
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

			votes, signature, userIDs, err := stop.Stop(r.Context(), id)

			if err != nil {
				handleError(w, err, true)
				return
			}

			if userIDs == nil {
				userIDs = []int{}
			}

			out := struct {
				Votes     json.RawMessage `json:"votes"`
				Signature []byte          `json:"signature"`
				Users     []int           `json:"user_ids"`
			}{
				votes,
				signature,
				userIDs,
			}

			if err := json.NewEncoder(w).Encode(out); err != nil {
				handleError(w, fmt.Errorf("encoding and sending objects: %w", err), true)
				return
			}
		},
	)
}

type clearer interface {
	Clear(ctx context.Context, pollID int) error
}

func handleClear(mux *http.ServeMux, clear clearer) {
	mux.HandleFunc(
		httpPathInternal+"/clear",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving clear request")
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
			log.Info("Receiving clear all request")
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

type authenticater interface {
	Authenticate(http.ResponseWriter, *http.Request) (context.Context, error)
	FromContext(context.Context) int
}

func handleVote(mux *http.ServeMux, vote voter, auth authenticater) {
	mux.HandleFunc(
		httpPathExternal,
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving vote request")
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

func handleVoted(mux *http.ServeMux, voted votedPollser, auth authenticater) {
	mux.HandleFunc(
		httpPathExternal+"/voted",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving has voted request")
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
	VoteCount(ctx context.Context) (map[int]int, error)
}

func handleVoteCount(mux *http.ServeMux, voteCounter voteCounter, eventer func() (<-chan time.Time, func())) {
	mux.HandleFunc(
		httpPathInternal+"/vote_count",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving vote count request")
			w.Header().Set("Content-Type", "application/json")

			encoder := json.NewEncoder(w)

			event, cancel := eventer()
			defer cancel()

			var lastCount map[int]int
			firstData := true
			for {
				count, err := voteCounter.VoteCount(r.Context())
				if err != nil {
					handleError(w, err, true)
					return
				}

				if lastCount == nil {
					lastCount = count
				} else {
					for k := range lastCount {
						if _, ok := count[k]; !ok {
							count[k] = 0
						}
						if count[k] == lastCount[k] {
							delete(count, k)
							continue
						}
						lastCount[k] = count[k]
					}
				}

				if firstData || len(count) > 0 {
					firstData = false
					if err := encoder.Encode(count); err != nil {
						handleError(w, err, true)
						return
					}
				}

				// This could be in the if(count) block, but the Flush is used
				// in the tests and has to be called, even when there is no data
				// to sent.
				w.(http.Flusher).Flush()

				select {
				case _, ok := <-event:
					if !ok {
						return
					}
				case <-r.Context().Done():
					return
				}
			}
		},
	)
}

func handleHealth(mux *http.ServeMux) {
	mux.HandleFunc(
		httpPathExternal+"/health",
		func(w http.ResponseWriter, r *http.Request) {
			log.Info("Receiving health request")
			w.Header().Set("Content-Type", "application/json")

			fmt.Fprintf(w, `{"healthy":true}`)
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

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}

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
