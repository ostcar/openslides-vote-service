package vote

import (
	"encoding/json"
	"fmt"
)

const (
	// ErrInternal should not happen.
	ErrInternal TypeError = iota

	// ErrExists happens, when start is called with an poll ID that already
	// exists.
	ErrExists

	// ErrNotExists happens when an operation is performed on an unknown poll.
	ErrNotExists

	// ErrInvalid happens, when the vote data is invalid.
	ErrInvalid

	// ErrDoubleVote happens on a vote request, when the user tries to vote for a
	// second time.
	ErrDoubleVote

	// ErrNotAllowed happens on a vote request, when the request user is
	// anonymous or is not allowed to vote.
	ErrNotAllowed

	// ErrStopped happens when a user tries to vote on a stopped poll.
	ErrStopped
)

// TypeError is an error that can happend in this API.
type TypeError int

// Type returns a name for the error.
func (err TypeError) Type() string {
	switch err {
	case ErrExists:
		return "exist"

	case ErrNotExists:
		return "not-exist"

	case ErrInvalid:
		return "invalid"

	case ErrDoubleVote:
		return "douple-vote"

	case ErrNotAllowed:
		return "not-allowed"

	case ErrStopped:
		return "stopped"

	default:
		return "internal"
	}
}

func (err TypeError) Error() string {
	var msg string
	switch err {
	case ErrExists:
		msg = "Poll does already exist with differet config"

	case ErrNotExists:
		msg = "Poll does not exist"

	case ErrInvalid:
		msg = "The input data is invalid"

	case ErrDoubleVote:
		msg = "Not the first vote"

	case ErrStopped:
		msg = "The vote is not open for votes"

	case ErrNotAllowed:
		msg = "You are not allowed to vote"

	default:
		msg = "Ups, something went wrong!"

	}
	return fmt.Sprintf(`{"error":"%s","message":"%s"}`, err.Type(), msg)
}

// MessageError is a TypeError with an individuel error message.
type MessageError struct {
	TypeError
	msg string
}

func (err MessageError) Error() string {
	out := struct {
		Error string `json:"error"`
		MSG   string `json:"message"`
	}{
		err.Type(),
		err.msg,
	}

	decoded, jsonerr := json.Marshal(out)
	if jsonerr != nil {
		return fmt.Sprintf(`{"error":"internal", "message":"someting went wrong encoding the error message"}`)
	}
	return string(decoded)
}

func (err MessageError) Unwrap() error {
	return err.TypeError
}
