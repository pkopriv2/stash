package httppolicy

import http "github.com/cott-io/stash/lang/http/server"

func Handlers(svc *http.Service) {
	GroupHandlers(svc)
	PolicyHandlers(svc)
}
