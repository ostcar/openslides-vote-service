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

// WithListToContent takes a function that is used to create the content
// returned from the Stop() call.
//
// The function taks an id and the randomized list of decrypted votes and
// createa the output format.
func WithListToContent(f func(id string, decrypted [][]byte) ([]byte, error)) Option {
	return func(d *Decrypt) {
		d.listToContent = f
	}
}
