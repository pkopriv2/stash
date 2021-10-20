package httpaccount

import (
	client "github.com/cott-io/stash/http/client/httpaccount"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func Identity(val string, raw interface{}) (err error) {
	*raw.(*auth.Identity), err = auth.ByStdUri(val)
	return
}

func AccountIdentityHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/verify"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts := core.AssignAccounts(env)

			var r client.IdentityVerifyRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(r.Id, "Item missing identity"),
				http.NotZero(r.Attempt, "Item missing attempt"),
			); ret != nil {
				return
			}

			identity, exists, err := accts.LoadIdentity(r.Id)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if !exists || identity.Deleted {
				ret = http.NotFound(
					errors.Wrapf(account.ErrNoIdentity, "That identity does not exist [%v]", r.Id))
				return
			}

			if identity.Verified {
				ret = http.Conflict(
					errors.Wrapf(account.ErrIdentityVerified, "That identity has already been claimed [%v]", r.Id))
				return
			}

			identity, err = identity.Update(account.IdentityVerify(r.Attempt))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := accts.SaveIdentity(identity); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Post("/v1/identities"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts, signer :=
				core.AssignAccounts(env),
				core.AssignSigner(env)

			var r client.IdentityRegisterRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(r.AcctId, "Missing account_id"),
				http.NotZero(r.Id, "Missing identity"),
			); ret != nil {
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsAccount(r.AcctId)); err != nil {
				ret = http.Unauthorized(err)
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

			identity, err := createIdentity(env, r.AcctId, r.Id, r.Opts)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if exists {
				identity, err = prev.Update(account.IdentityReset(identity.AccountId, identity.Verifier, r.Opts))
				if err != nil {
					ret = http.Panic(err)
					return
				}
			}

			if err := accts.SaveIdentity(identity); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Get("/v1/identities/{id}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts, signer :=
				core.AssignAccounts(env),
				core.AssignSigner(env)

			var id auth.Identity
			if err := http.RequirePathParam(req, "id", Identity, &id); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			identity, exists, err := accts.LoadIdentity(id)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !exists || identity.Deleted || !identity.Verified {
				ret = http.NotFound(errors.Wrapf(account.ErrNoIdentity, "No such identity [%v]", id))
				return
			}

			ret = http.Ok(enc.Json, identity.Info())
			return
		})

	svc.Register(http.Get("/v1/identities"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts, signer :=
				core.AssignAccounts(env),
				core.AssignSigner(env)

			var acctId uuid.UUID
			if err := http.RequireQueryParam(req, "account_id", http.UUID, &acctId); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset uint64 = 0
			var limit uint64 = 256
			if err :=
				http.ParseQueryParams(req,
					http.Param("offset", http.Uint64, &offset),
					http.Param("limit", http.Uint64, &limit)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsAccount(acctId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			identities, err := accts.ListIdentities(acctId, page.BuildPage(
				page.Offset(offset),
				page.Limit(limit)))
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Ok(enc.Json, identities)
			return
		})

	svc.Register(http.Delete("/v1/identities/{id}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, db :=
				core.AssignSigner(env),
				core.AssignAccounts(env)

			var id auth.Identity
			if err := http.RequirePathParam(req, "id", Identity, &id); err != nil {
				ret = http.BadRequest(err)
				return
			}

			identity, found, err := db.LoadIdentity(id)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if !found || identity.Deleted {
				ret = http.StatusNotFound
				return
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsAccount(identity.AccountId),
				auth.IsNotIdentity(id)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			identity, err = identity.Update(account.IdentityDelete)
			if err != nil {
				ret = http.Conflict(err)
				return
			}

			if err := db.SaveIdentity(identity); err != nil {
				ret = http.Panic(err)
				return
			}

			env.Logger().Debug("Removed identity [%v] from account [%v]", id, identity.AccountId)
			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Post("/v1/identities_list"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			accts, signer :=
				core.AssignAccounts(env),
				core.AssignSigner(env)

			var r client.ListIdentitiesRequest
			if err := http.RequireStruct(req, enc.DefaultRegistry, &r); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			idents, err := accts.ListIdentitiesByIds(r.Ids)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			identsByAcccountIds := make(map[uuid.UUID][]account.Identity)
			for _, id := range idents {
				ids, ok := identsByAcccountIds[id.AccountId]
				if !ok {
					ids = []account.Identity{}
				}
				if id.Private {
					continue
				}
				identsByAcccountIds[id.AccountId] = append(ids, id.Info())
			}

			ret = http.Ok(enc.Json, identsByAcccountIds)
			return
		})
}
