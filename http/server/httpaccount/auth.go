package httpaccount

import (
	client "github.com/cott-io/stash/http/client/httpaccount"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

var NoId = uuid.UUID{}

// Register all the server handlers
func AccountAuthHandlers(svc *http.Service) {
	svc.Register(
		http.Post("/v1/auth"), func(env env.Environment, req http.Request) (ret http.Response) {
			logger, signer := env.Logger(), core.AssignSigner(env)

			var r client.AuthRequest
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

			logger.Debug("Attempting to authenticate [user=%v]", r.Id)

			// Handle: Account authentication
			identity, login, err := authAccount(env, r.Id, r.Attempt, r.Opts)
			if err != nil {
				ret = http.Unauthorized(err)
				return
			}

			claims := auth.BuildClaim(
				auth.ClaimExpires(r.Opts.Expires),
				auth.ClaimAccount(identity.Id, identity.AccountId),
				auth.ClaimLogin(login.Uri, login.Version))

			// Handle: Org authentication
			if r.Opts.OrgId != NoId {
				orgn, err := authOrg(env, identity.AccountId, r.Opts.OrgId)
				if err != nil {
					ret = http.Unauthorized(err)
					return
				}

				claims = claims.Amend(auth.ClaimMember(r.Opts.OrgId, orgn.Role))
			}

			token, err := auth.SignClaims(signer, claims)
			if err != nil {
				ret = http.Panic(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, token),
				http.WithBearer(token.String()))
			return
		})
}

func authAccount(env env.Environment, id auth.Identity, attmpt auth.Attempt, opts auth.AuthOptions) (root account.Identity, login account.Login, err error) {
	accts := core.AssignAccounts(env)

	root, err = core.RequireIdentity(accts, id)
	if err != nil {
		err = errors.Wrapf(err, "Error loading identity [%v]", id)
		return
	}

	if root.DeviceId != "" {
		if root.DeviceId != opts.DeviceId {
			err = errors.Wrapf(auth.ErrUnauthorized, "Invalid device id")
			return
		}
	}

	settings, _, err := accts.LoadSettings(root.AccountId)
	if err != nil {
		err = errors.Wrapf(err, "Error loading settings [%v]", root.AccountId)
		return
	}

	if !settings.Enabled {
		err = errors.Wrap(auth.ErrUnauthorized, "Your account has been disabled.")
		return
	}

	login, err = core.RequireLogin(accts, root.AccountId, attmpt.Uri())
	if err != nil {
		err = errors.Wrapf(err, "Error loading login [%v]", root.AccountId)
		return
	}

	err = login.Validate(enc.Json, attmpt)
	return
}

func authOrg(env env.Environment, acctId, orgId uuid.UUID) (mem org.Member, err error) {
	mem, ok, err := core.AssignOrgs(env).LoadMember(orgId, acctId)
	if err != nil {
		return
	}
	if !ok {
		err = errors.Wrapf(auth.ErrUnauthorized, "No membership to org")
		return
	}
	return
}
