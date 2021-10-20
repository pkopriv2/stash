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

func BlockHandlers(svc *http.Service) {
	svc.Register(http.Post("/v1/orgs/{orgId}/blocks"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, secrets :=
				core.AssignSigner(env),
				core.AssignSecrets(env)

			var orgId uuid.UUID
			if err := http.RequirePathParams(req,
				http.Param("orgId", http.UUID, &orgId)); err != nil {
				ret = http.BadRequest(err)
				return
			}

			var blocks []secret.Block
			if err := http.RequireStruct(req, enc.DefaultRegistry, &blocks); err != nil {
				ret = http.BadRequest(err)
				return
			}

			if len(blocks) < 1 {
				ret = http.BadRequest(errors.Wrapf(errs.ArgError, "No blocks provided"))
				return
			}

			for _, b := range blocks {
				if ret = http.First(
					http.NotZero(b.OrgId, "Block missing org id"),
					http.NotZero(b.StreamId, "Block missing stream id"),
					http.AssertTrue(b.OrgId == orgId,
						"Inconsistent org ids"),
					http.AssertTrue(b.OrgId == blocks[0].OrgId,
						"Inconsistent org ids"),
					http.AssertTrue(b.StreamId == blocks[0].StreamId,
						"Inconsistent org ids"),
				); ret != nil {
					return
				}
			}

			if err := auth.AssertClaims(req, signer.Public(),
				auth.IsMember(orgId, auth.Member)); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			// TODO: VALIDATE POLICY!!

			if err := secrets.SaveBlocks(blocks...); err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.StatusNoContent
			return
		})

	svc.Register(http.Get("/v1/orgs/{orgId}/blocks/{secretId}"),
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
			var version int
			if err := http.ParseQueryParams(req,
				http.Param("offset", http.Uint64, &offset),
				http.Param("limit", http.Uint64, &limit),
				http.Param("version", http.Int, &version),
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

			sec, ok, err := secrets.LoadSecretById(orgId, secretId, version)
			if err != nil {
				ret = http.Panic(err)
				return
			}
			if !ok {
				ret = http.StatusNotFound
				return
			}

			if err := policy.Authorize(policies, claim.Account.Id,
				policy.Has(policy.View), sec); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			blocks, err := secrets.LoadBlocks(sec.OrgId, sec.StreamId, page.Page{
				Offset: offset,
				Limit:  limit})
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Ok(enc.Json, blocks)
			return
		})
}
