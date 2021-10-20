package httpaccount

import (
	client "github.com/cott-io/stash/http/client/httpaccount"
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

func AccountLoginHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/accounts/{id}/logins"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, accts :=
				core.AssignSigner(env),
				core.AssignAccounts(env)

			var acctId uuid.UUID
			if err := http.RequirePathParam(req, "id", http.UUID, &acctId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var r client.LoginRegisterRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.AssertTrue(r.Shard.AccountId == acctId, "Inconsistent ids"); ret != nil {
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsAccount(acctId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			login, ok, err := accts.LoadLogin(acctId, r.Attempt.Uri())
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if !ok {
				login, err = account.NewLogin(enc.Json, acctId, r.Attempt)
				if err != nil {
					ret = http.Panic(err)
					return
				}
			} else {
				login, err = login.Update(account.LoginReset(crypto.Rand, enc.Json, r.Attempt))
				if err != nil {
					ret = http.Panic(err)
					return
				}
			}

			if err := accts.SaveLogin(login, r.Shard.Update(account.UpdateShardVersion(login.Version))); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Delete("/v1/accounts/{id}/logins/{uri}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, accts :=
				core.AssignSigner(env),
				core.AssignAccounts(env)

			var acctId uuid.UUID
			var uri string
			if err := http.RequirePathParams(req,
				http.Param("id", http.UUID, &acctId),
				http.Param("uri", http.UUID, &acctId),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsAccount(acctId),
				auth.IsNotLogin(uri)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			login, ok, err := accts.LoadLogin(acctId, uri)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if !ok {
				ret = http.NotFound(errors.Wrapf(account.ErrNoLogin, "No such login [%v]", uri))
				return
			}

			login, err = login.Update(account.LoginDelete)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if err := accts.SaveLogin(login, account.LoginShard{}); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})
}
