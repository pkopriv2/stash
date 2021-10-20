package session

import (
	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

// Register registers a new account with the service.
func Register(ctx context.Context, id auth.Identity, login auth.Login, fns ...Option) (err error) {
	opts, err := buildOptions(fns...)
	if err != nil {
		return
	}

	creds, err := auth.ExtractCreds(login)
	if err != nil {
		return
	}
	defer creds.Destroy()

	acct, shard, err := account.NewSecret(crypto.Rand, uuid.NewV4(), creds, opts.Strength)
	if err != nil {
		err = errors.Wrapf(err, "Error generating account secret [%v]", id.Uri())
		return
	}

	secret, err := acct.DeriveSecret(creds, shard)
	if err != nil {
		return
	}
	defer secret.Destroy()

	signer, err := acct.UnlockKey(secret)
	if err != nil {
		return
	}
	defer crypto.Destroy(signer)

	attmpt, err := creds.Auth(crypto.Rand)
	if err != nil {
		return
	}

	return opts.Accounts().Register(id, attmpt, acct, shard,
		auth.BuildIdentityOptions(
			auth.WithProof(attmpt)))
}
