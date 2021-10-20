package httpaccount

import (
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	uuid "github.com/satori/go.uuid"
)

func AccountSecretHandlers(svc *http.Service) {
	svc.Register(http.Get("/v1/accounts/{id}/secret/{uri}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignAccounts(env)

			var acctId uuid.UUID
			var uri string
			if err := http.RequirePathParams(req,
				http.Param("id", http.UUID, &acctId),
				http.Param("uri", http.String, &uri),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var version int
			if err := http.RequireQueryParam(req, "version", http.Int, &version); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsAccount(acctId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			secret, found, err := db.LoadSecret(acctId)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !found {
				ret = http.StatusNotFound
				return
			}

			shard, found, err := db.LoadLoginShard(acctId, uri, version)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !found {
				ret = http.StatusNotFound
				return
			}
			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, account.SecretAndShard{secret, shard}))
			return
		})
}
