package httporg

import (
	client "github.com/cott-io/stash/http/client/httporg"
	"github.com/cott-io/stash/http/core"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	http "github.com/cott-io/stash/lang/http/server"
	"github.com/cott-io/stash/libs/auth"
)

func BillingHandlers(svc *http.Service) {
	svc.Register(http.Get("/v1/system/billing_key"),
		func(env env.Environment, req http.Request) (ret http.Response) {
			signer, key :=
				core.AssignSigner(env),
				core.AssignBillingKey(env)

			if err := auth.AssertClaims(req, signer.Public(), auth.IsNotExpired()); err != nil {
				ret = http.Unauthorized(err)
				return
			}

			ret = http.Reply(
				http.StatusOK,
				http.WithStruct(enc.Json, client.BillingKeyResponse{key}))
			return
		})
}
