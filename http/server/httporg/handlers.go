package httporg

import http "github.com/cott-io/stash/lang/http/server"

func Handlers(svc *http.Service) {
	BillingHandlers(svc)
	OrgHandlers(svc)
	MemberHandlers(svc)
	PlanHandlers(svc)
}
