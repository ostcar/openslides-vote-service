package decrypt

import "io"

// Option for decrypt.New()
type Option = func(*Decrypt)

// WithRandomSource sets the random source. Uses crypt/rand.Reader as default.
//
// Should only be used for testing.
func WithRandomSource(r io.Reader) Option {
	return func(d *Decrypt) {
		d.random = r
	}
}

// WithMaxVotes sets the number of maximum votes, that are supported.
func WithMaxVotes(maxVotes int) Option {
	return func(d *Decrypt) {
		d.maxVotes = maxVotes
	}
}
