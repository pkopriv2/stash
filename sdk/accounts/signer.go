package accounts

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/sdk/session"
	"github.com/denisbrodbeck/machineid"
)

// Adds a cryptographic signer to the account
func AddSigner(s session.Session, signer crypto.Signer, opts ...auth.IdentityOption) (err error) {
	id, login := auth.ByKey(signer.Public()), auth.WithSignature(signer, s.Options().Strength)

	cred, err := auth.ExtractCreds(login)
	if err != nil {
		return
	}
	defer cred.Destroy()

	attmpt, err := cred.Auth(crypto.Rand)
	if err != nil {
		return
	}

	deviceId, err := machineid.ProtectedID("stash")
	if err != nil {
		return
	}

	return errs.Or(
		AddLogin(s, login),
		AddIdentity(s, id, append(opts, auth.WithProof(attmpt), auth.WithDeviceID(deviceId))...))
}

// Deletes a signer from the account.
func DeleteSignerById(s session.Session, key string) (err error) {
	return errs.Or(
		DeleteIdentity(s, auth.ByKeyId(key)),
		DeleteLogin(s, auth.SignatureAuthUriById(key)))
}
