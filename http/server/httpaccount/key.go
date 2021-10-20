package httpaccount

import (
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func AccountKeyHandlers(svc *http.Service) {
	svc.Register(http.Get("/v1/accounts/{id}/key"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts, signer :=
				core.AssignAccounts(env),
				core.AssignSigner(env)

			var acctId uuid.UUID
			if err := http.RequirePathParam(req, "id", http.UUID, &acctId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			secret, ok, err := accts.LoadSecret(acctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.NotFound(errors.Wrapf(account.ErrNoAccount, "No such account [%v]", acctId))
				return
			}

			ret = http.Ok(enc.Json, crypto.EncodableKey{secret.Chain.Key.Pub})
			return
		})
}
