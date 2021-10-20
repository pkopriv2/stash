package httpaccount

import http "github.com/cott-io/stash/lang/http/server"

func Handlers(svc *http.Service) {
	AccountAuthHandlers(svc)
	AccountRegisterHandlers(svc)
	AccountSecretHandlers(svc)
	AccountIdentityHandlers(svc)
	AccountLoginHandlers(svc)
	AccountKeyHandlers(svc)
}
