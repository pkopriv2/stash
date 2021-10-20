package auth

// THIS PACKAGE IS INTERNAL ONLY.  THE STABILITY GUARANTEES OF WARDEN DO NOT APPLY HERE!
import (
	"io"
	"math/big"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/pkg/errors"
)

var (
	ErrNoCredential = errors.New("Auth:ErrNoCredential")
	ErrAuthAttempt  = errors.New("Auth:ErrAuthAttempt")
	ErrBadArgs      = errors.New("Auth:ErrAuthBadArgs")
	ErrBadProtocol  = errors.New("Auth:ErrBadProtocol")
	ErrRSA          = errors.New("crypto/rsa: verification error")
)

var (
	MaxCode = big.NewInt(1000000)
)

// *** LOGIN + CREDENTIALS *** //

// A credential manages the client-side components of the login protocol.  In order
// to initiate the login, the consumer must provide two pieces of knowledge:
//
//   * an account lookup
//   * an authentication value
//
// For security reasons, credentials are short-lived.  Credentials are obtained
// by using various login methods.
//
// ```
// creds, err := auth.ExtractCreds(auth.WithPemFile("key.pem"))
// ```
//
type Credential interface {
	crypto.Destroyer

	// Authenticator uri.
	Uri() string

	// Produces an authentication attempt.
	Auth(io.Reader) (Attempt, error)

	// Applies the salt to the credential
	Salt(salt crypto.Salt, size int) (crypto.Bytes, error)
}

// A login wraps the secure elements of the credentials into a closure
// that may be invoked when necessary.  For secure environments, this
// may mean making a call to io devices or signing devices.
type Login func() (Credential, error)

// An attempt contains all the data necessary to demonstrate an
// an attempt at authentication
type Attempt interface {
	Type() string
	Uri() string
	Args(interface{}) error
}

// An authenticator is responsible for validating an auth attempt
type Authenticator interface {
	Type() string
	Uri() string
	Validate(Attempt) error
}

// Extract credentials from a login closure
func ExtractCreds(fn Login) (Credential, error) {
	creds, err := fn()
	if err != nil {
		return nil, errors.Wrap(err, "Error extracting credentials")
	}
	if creds == nil {
		return nil, errors.Wrap(ErrNoCredential, "No credentials entered")
	}
	return creds, nil
}

// Generates a serializable authenticator from the attempt.
func NewAuthenticator(rand io.Reader, attmpt Attempt) (ret Authenticator, err error) {
	switch attmpt.Type() {
	default:
		err = errors.Wrapf(ErrBadProtocol, "Unsupported protocol [%v]", attmpt.Type())
		return
	case PasswordProtocol:
		var args PasswordAttempt
		if err = attmpt.Args(&args); err != nil {
			return
		}

		return NewPasswordAuth(rand, args)
	case SignatureProtocol:
		var args SignatureAttempt
		if err = attmpt.Args(&args); err != nil {
			return
		}

		return NewSignatureAuth(args)
	}
}
