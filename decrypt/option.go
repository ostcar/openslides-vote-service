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
