package httpsecret

import (
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	"github.com/cott-io/stash/lang/errs"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func SecretHandlers(svc *http.Service) {

	svc.Register(http.Post("/v1/orgs/{orgId}/secrets"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies, secrets :=
				core.AssignSigner(env),
				core.AssignPolicies(env),
				core.AssignSecrets(env)

			var orgId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var sec secret.Secret
			if err := http.RequireStruct(req, enc.DefaultRegistry, &sec); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if ret = http.First(
				http.NotZero(sec.Id, "Missing secret id"),
				http.NotZero(sec.OrgId, "Missing policy id"),
				http.NotZero(sec.PolicyId, "Missing policy id"),
				http.NotZero(sec.AuthorId, "Missing author id"),
				http.AssertTrue(sec.OrgId == orgId,
					"Inconsistent org ids"),
			); ret != nil {
				return
			}

			claim, err := auth.ParseAndAssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			cur, exists, err := secrets.LoadSecretById(sec.OrgId, sec.Id, -1)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			// If there is already one existence, we may be restoring!
			action := policy.Edit
			if exists && cur.Deleted && !sec.Deleted {
				action = secret.Restore
			} else if sec.Deleted {
				action = policy.Delete
			}

			if err := policy.Authorize(policies, claim.Account.Id,
				policy.Has(action),
				policy.New(sec.OrgId, sec.PolicyId)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			if err := secrets.SaveSecret(sec); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Post("/v1/orgs/{orgId}/secrets_list"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies, secrets :=
				core.AssignSigner(env),
				core.AssignPolicies(env),
				core.AssignSecrets(env)

			var orgId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var filter secret.Filter
			if err := http.RequireStruct(req, enc.DefaultRegistry, &filter); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset, limit *uint64
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			claim, err := auth.ParseAndAssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			results, err := secrets.ListSecrets(orgId, filter, page.Page{Offset: offset, Limit: limit})
			if err != nil {
				ret = http.Panic(err)
				return
			}

			summaries, err := secret.DecorateSecrets(policies, claim.Account.Id, results...)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Ok(enc.Json, summaries)
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/secrets/{secretId}"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies, secrets :=
				core.AssignSigner(env),
				core.AssignPolicies(env),
				core.AssignSecrets(env)

			var orgId, secretId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("secretId", http.UUID, &secretId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var version int = -1
			if err := http.ParseQueryParams(req,
				http.Param("version", http.Int, &version)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			claim, err := auth.ParseAndAssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			sec, ok, err := secrets.LoadSecretById(orgId, secretId, version)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.NotFound(errors.Wrapf(errs.ArgError, "No such secret [%v]", secretId))
				return
			}

			if version >= 0 {
				if err = policy.Authorize(policies, claim.Account.Id,
					policy.Has(secret.Restore, policy.Sudo)); err != nil {
					ret = http.Unauthorized(err)
					return
				}
			}

			ret = http.Ok(enc.Json, sec)
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/secrets/{secretId}/versions"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, policies, secrets :=
				core.AssignSigner(env),
				core.AssignPolicies(env),
				core.AssignSecrets(env)

			var orgId, secretId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId),
				http.Param("secretId", http.UUID, &secretId),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var offset, limit *uint64
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit),
			); err != nil {
				ret = http.BadRequest(err)
				return
			}

			claim, err := auth.ParseAndAssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member))
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			revs, err := secrets.ListSecretVersions(orgId, secretId, page.Page{Offset: offset, Limit: limit})
			if err != nil {
				ret = http.Panic(err)
				return
			}

			if len(revs) > 0 {
				if err = policy.Authorize(policies, claim.Account.Id,
					policy.HasAny(
						secret.Restore,
						policy.Sudo),
					revs[0]); err != nil {
					ret = http.Unauthorized(err)
					return
				}
			}

			ret = http.Ok(enc.Json, revs)
			return
		})
}
