package errorcode

const (
	// Unknown is not known by the decrypt error.
	Unknown DecryptError = iota

	// Exist happens when the content already exist.
	//
	// Has to be returned by store.SaveKey() when the key already exists.
	Exist

	// NotExist happens when the content does not exist.
	//
	// Has to be returned by store.LoadKey() when key is unknown.
	NotExist

	// Invalid happens when the given data is invalid
	//
	// Has to be returned by store.ValidateHash if the hash is invalid.
	Invalid
)

// DecryptError are all known errors from the decrypt error.
type DecryptError int

func (err DecryptError) Error() string {
	switch err {
	case Exist:
		return "content already exists"

	case NotExist:
		return "content does not exists"

	case Invalid:
		return "invalid content"

	default:
		return "unknown error"
	}
}
