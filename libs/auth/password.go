package auth

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/term"
	"github.com/pkg/errors"
)

const (
	PasswordProtocol = "pass/0.1"
	PasswordUri      = "password://default"
)

type PasswordCred struct {
	pass crypto.Bytes
	hash crypto.Hash
}

func newPassCred(raw crypto.Bytes, hash crypto.Hash) (Credential, error) {
	hashed, err := raw.Copy().Hash(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return &PasswordCred{hashed, hash}, nil
}

func (p *PasswordCred) Destroy() {
	// crypto.Destroy(p.pass)
}

func (p *PasswordCred) Uri() string {
	return PasswordUri
}

func (p *PasswordCred) Auth(io.Reader) (ret Attempt, err error) {
	val, err := p.pass.Hash(p.hash)
	if err != nil {
		return
	}
	ret = PasswordAttempt{p.Uri(), val}
	return
}

func (p *PasswordCred) Salt(salt crypto.Salt, size int) (crypto.Bytes, error) {
	return salt.Apply(p.pass, size), nil
}

type PasswordAttempt struct {
	URI  string       `json:"uri"`
	Hash crypto.Bytes `json:"hash"`
}

func (p PasswordAttempt) Type() string {
	return PasswordProtocol
}

func (p PasswordAttempt) Uri() string {
	return p.URI
}

func (p PasswordAttempt) Args(raw interface{}) (err error) {
	ptr, ok := raw.(*PasswordAttempt)
	if !ok {
		err = errors.Wrapf(errs.ArgError, "Unexpected authentication arguments [%v]", raw)
		return
	}
	*ptr = p
	return
}

// The server component (or the password based auth protocol)
type PasswordAuth struct {
	Typ  string       `json:"type"`
	URI  string       `json:"uri"`
	Salt crypto.Salt  `json:"salt"`
	Auth crypto.Bytes `json:"auth"`
}

func NewPasswordAuth(rand io.Reader, args PasswordAttempt) (ret Authenticator, err error) {
	salt, err := crypto.GenSalt(rand)
	if err != nil {
		return
	}

	ret = PasswordAuth{args.Type(), args.Uri(), salt, salt.Apply(args.Hash, len(salt.Nonce))}
	return
}

func (p PasswordAuth) Type() string {
	return p.Typ
}

func (p PasswordAuth) Uri() string {
	return p.URI
}

func (p PasswordAuth) Validate(auth Attempt) (err error) {
	if p.Type() != auth.Type() {
		err = errors.Wrapf(errs.ArgError, "Unexpected authentication algorithm [%v]. Expected [%v]", auth.Type(), p.Type())
		return
	}

	var args PasswordAttempt
	if err = auth.Args(&args); err != nil {
		err = errors.Wrapf(errs.ArgError, "Incompatible attempt [%v]", auth)
		return
	}

	if !p.Auth.Equals(p.Salt.Apply(args.Hash, len(p.Salt.Nonce))) {
		err = errors.Wrapf(ErrAuthAttempt, "Failed authentication attempt.")
		return
	}

	return
}

// Returns a credential closure generated from the password.  The original
// password is immediately hashed and is destroyed.
func WithPassword(pass []byte) Login {
	defer crypto.Destroy(crypto.Bytes(pass))
	cred, err := newPassCred(pass, crypto.SHA256)
	return func() (Credential, error) {
		return cred, err
	}
}

// Returns a credential closure generated from the password.  The original
// password is immediately hashed and is destroyed.
func WithTerminalPassword(term term.Terminal, prompt string) Login {
	var cred Credential
	return func() (ret Credential, err error) {
		if cred == nil {
			var raw []byte

			// read the password
			if err = term.PromptPassword(prompt, &raw); err != nil {
				return
			}
			defer crypto.Bytes(raw).Destroy()

			// initialize the credential
			cred, err = newPassCred(raw, crypto.SHA256)
			if err != nil {
				return
			}
		}

		ret = cred
		return
	}
}

// Returns a randomly generated numeric password as a UTF-8 encoded string.
func RandomPassword(r io.Reader) (crypto.Bytes, error) {
	n, err := rand.Int(r, MaxCode)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%v", n)), nil
}
