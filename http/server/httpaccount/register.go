package httpaccount

import (
	client "github.com/cott-io/stash/http/client/httpaccount"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	"github.com/cott-io/stash/lang/errs"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/lang/msgs"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func AccountRegisterHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/accounts"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts := core.AssignAccounts(env)

			var r client.RegisterRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			prev, exists, err := accts.LoadIdentity(r.Id)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if prev.Verified {
				ret = http.Conflict(
					errors.Wrapf(account.ErrAccountExists, "That identity has already been claimed [%v]", r.Id))
				return
			}

			root, err := createIdentity(env, r.Secret.AccountId, r.Id, r.Opts)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if exists {
				root, err = prev.Update(account.IdentityReset(root.AccountId, root.Verifier, r.Opts))
				if err != nil {
					ret = http.Panic(err)
					return
				}
			}

			login, err := account.NewLogin(enc.Json, r.Secret.AccountId, r.Attempt)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			settings := account.NewSettings(r.Secret.AccountId)
			if err = accts.CreateAccount(root, login, r.Secret, r.Shard, settings); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent

			//_, err = deps.CreatePrivateOrg(deps.DemandOrgs(env), req.Snapshot(), r.Secret.Id)
			//if err != nil {
			//ret = http.Panic(err)
			//return
			//}

			return
		})
}

func createIdentity(env env.Environment, acctId uuid.UUID, id auth.Identity, opts auth.IdentityOptions) (ret account.Identity, err error) {
	var verifier auth.Authenticator
	switch id.Protocol() {
	default:
		err = errors.Wrapf(errs.ArgError, "Unsupported protocol [%v]", id.Protocol())
		return
	case auth.Email, auth.Phone:
		code, err := auth.RandomPassword(crypto.Rand)
		if err != nil {
			return account.Identity{}, err
		}
		defer crypto.Destroy(code)

		cred, err := auth.ExtractCreds(auth.WithPassword(code.Copy()))
		if err != nil {
			return account.Identity{}, err
		}

		attmpt, err := cred.Auth(crypto.Rand)
		if err != nil {
			return account.Identity{}, err
		}

		verifier, err = auth.NewAuthenticator(crypto.Rand, attmpt)
		if err != nil {
			return account.Identity{}, err
		}

		if err := verifier.Validate(attmpt); err != nil {
			return account.Identity{}, err
		}

		msg := NewVerifyMessage(id, string(code.Copy()))
		if id.Protocol() == auth.Email {
			err = msgs.SendMail(core.AssignMailer(env), msg)
		} else {
			err = msgs.SendText(core.AssignTexter(env), msg)
		}
		if err != nil {
			env.Logger().Error("Error sending verification code to [%v]: %+v", id, err)
			return account.Identity{}, err
		}

		env.Logger().Debug("Sent verification code to %v", id.Value())
	case auth.Key:
		env.Logger().Debug("Registering key [%v]", id)
		if opts.Proof == nil {
			return account.Identity{}, errors.Wrap(errs.ArgError, "Must provide proof of key ownership")
		}

		if opts.Proof.Attempt.Type() != auth.SignatureProtocol {
			return account.Identity{}, errors.Wrap(errs.ArgError, "Unexpected proof type")
		}

		if opts.Proof.Attempt.Uri() != auth.SignatureAuthUriById(id.Val) {
			return account.Identity{}, errors.Wrap(errs.ArgError, "Inconsistent proof uri")
		}

		auth, err := auth.NewAuthenticator(crypto.Rand, opts.Proof.Attempt)
		if err != nil {
			return account.Identity{}, err
		}

		if err := auth.Validate(opts.Proof.Attempt); err != nil {
			return account.Identity{}, errors.Wrapf(err, "Invalid signature with proof")
		}
	case auth.UUID, auth.User:
		// auto verified
	}
	return account.NewIdentity(acctId, id, verifier, opts)
}

func NewVerifyMessage(id auth.Identity, code string) msgs.Message {
	return msgs.Compile(VerifyTemplate, id.Value(), VerifyFields{id.Value(), code})
}

type VerifyFields struct {
	Identity string
	Code     string
}

// FIXME: Consider pulling these out into static content files!
var VerifyTemplate = msgs.BuildTemplate(
	"Verify Your Identity",

	msgs.AsMicro(`
Your Identity Verification Code:

{{.Code}}`),

	msgs.AsText(`
Verify Your Identity

Congratulations on your new Iron (Fe) account!

Here is your verfication code:

{{.Code}}

Verifying on the command line:

Verify your email on the command line by running the following command.

fe identity verify {{.Identity}} {{.Code}}

Not you?

Please contact support@cott.io if you believe you received this email by mistake.
`),

	msgs.AsMarkdown(`
### Verify Your Iron Identity

Congratulations on your new Iron (Fe) account!

Here is your verfication code:

### {{.Code}}

#### Verifying on the command line:

Verify your email on the command line by running the following command.

fe identity verify {{.Identity}} {{.Code}}

### Not you?

Please contact support@cott.io if you believe you received this email by mistake.
`))
