package session

import (
	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/env"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/denisbrodbeck/machineid"
	"github.com/pkg/errors"
)

// Starts a new authenticated session
func Authenticate(ctx context.Context, id auth.Identity, login auth.Login, opt ...Option) (ret Session, err error) {
	opts, err := buildOptions(opt...)
	if err != nil {
		return
	}

	creds, err := auth.ExtractCreds(login)
	if err != nil {
		err = errors.Wrap(err, "Unable to extract credentials")
		return
	}
	defer creds.Destroy()

	attmpt, err := creds.Auth(crypto.Rand)
	if err != nil {
		err = errors.Wrap(err, "Unable to generate auth attempt")
		return
	}

	deviceId, err := machineid.ProtectedID("stash")
	if err != nil {
		err = errors.Wrapf(err, "Unable to generate device id")
		return
	}

	token, err := opts.Accounts().Authenticate(id, attmpt,
		auth.BuildOptions(
			auth.WithTimeout(opts.Strength.TokenTimeout()),
			auth.WithDeviceId(deviceId)))
	if err != nil {
		err = errors.Wrap(err, "Unable to authenticate")
		return
	}

	secret, found, err := opts.Accounts().LoadSecretAndShard(token,
		token.Account.Id,
		token.Account.LoginUri,
		token.Account.LoginVersion)
	if err != nil {
		err = errors.Wrap(err, "Unable to load account secret")
		return
	}
	if !found {
		err = account.ErrNoLogin
		return
	}

	ret, err = newSession(env.NewEnvironment(ctx), id, login, secret.Secret, secret.LoginShard, opts)
	return
}
