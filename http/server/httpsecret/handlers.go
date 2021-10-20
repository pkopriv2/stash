package httpsecret

import http "github.com/cott-io/stash/lang/http/server"

func Handlers(svc *http.Service) {
	SecretHandlers(svc)
	BlockHandlers(svc)
}
