package account

import (
	"github.com/pkg/errors"
)

var (
	ErrNoAccount          = errors.New("Acct:NoAccount")
	ErrAccountExists      = errors.New("Acct:AccountExists")
	ErrAccountDisabled    = errors.New("Acct:AccountDisabled")
	ErrNoIdentity         = errors.New("Acct:NoIdentity")
	ErrIdentityVerified   = errors.New("Acct:IdentityVerified")
	ErrIdentityUnverified = errors.New("Acct:IdentityUnverified")
	ErrIdentityDisabled   = errors.New("Acct:IdentityDisabled")
	ErrIdentityRegistered = errors.New("Acct:IdentityRegistered")
	ErrNoLogin            = errors.New("Acct:NoLogin")
	ErrLoginDisabled      = errors.New("Acct:LoginDisabled")
	ErrLoginEnabled       = errors.New("Acct:LoginEnabled")
)
