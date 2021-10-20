package httporg

import (
	"github.com/cott-io/stash/lang/billing"
	"github.com/cott-io/stash/lang/enc"
	http "github.com/cott-io/stash/lang/http/client"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type BillingKeyResponse struct {
	Key string `json:"key"`
}

type PurchaseRequest struct {
	Name     string       `json:"name"`
	Purchase org.Purchase `json:"purchase"`
}

type CreateMemberRequest struct {
	AcctId uuid.UUID `json:"account_id"`
	Role   auth.Role `json:"role"`
}

type UpdateMemberRequest struct {
	Role auth.Role `json:"role"`
}

type UpdateSubscriptionRequest struct {
	Purchase org.Purchase `json:"purchase"`
}

type ListRequest struct {
	Ids []uuid.UUID `json:"ids"`
}

type HttpClient struct {
	Raw http.Client
	Reg enc.Registry
}

func NewClient(raw http.Client, reg enc.Registry) org.Transport {
	return &HttpClient{raw, reg}
}

func (h *HttpClient) LoadBillingKey(token auth.SignedToken) (ret string, err error) {
	var r BillingKeyResponse
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/system/billing_key"),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &r))
	ret = r.Key
	return
}

func (h *HttpClient) Purchase(token auth.SignedToken, name string, purchase org.Purchase) (ret org.Org, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs"),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json,
				PurchaseRequest{name, purchase})),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) ListOrgsByIds(token auth.SignedToken, ids []uuid.UUID) (ret []org.Org, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs_list"),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, ListRequest{ids})),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) LoadOrgById(token auth.SignedToken, orgId uuid.UUID) (ret org.Org, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v", orgId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) LoadOrgByName(token auth.SignedToken, name string) (ret org.Org, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs"),
			http.WithQueryParam("name", name),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) SaveOrg(token auth.SignedToken, o org.Org) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/orgs/%v", o.Id),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, o)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) CreateMember(token auth.SignedToken, orgId, acctId uuid.UUID, role auth.Role) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/members", orgId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json,
				CreateMemberRequest{acctId, role})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) UpdateMember(token auth.SignedToken, orgId, acctId uuid.UUID, role auth.Role) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/orgs/%v/members/%v", orgId, acctId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json,
				UpdateMemberRequest{role})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) DeleteMember(token auth.SignedToken, orgId, acctId uuid.UUID) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Delete("/v1/orgs/%v/members/%v", orgId, acctId),
			http.WithBearer(token.String())),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadMember(token auth.SignedToken, orgId, acctId uuid.UUID) (ret org.Member, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/members/%v", orgId, acctId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) ListMembersByOrgId(token auth.SignedToken, orgId uuid.UUID, page page.Page) (ret []org.Member, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/members", orgId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) ListMembersByAccountId(token auth.SignedToken, acctId uuid.UUID, page page.Page) (ret []org.Member, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/accounts/%v/members", acctId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) LoadSubscription(token auth.SignedToken, orgId uuid.UUID) (ret org.SubscriptionSummary, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/subscriptions/%v", orgId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) UpdateSubscription(token auth.SignedToken, orgId uuid.UUID, purchase org.Purchase) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/subscriptions/%v", orgId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, UpdateSubscriptionRequest{purchase})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) DeleteSubscription(token auth.SignedToken, orgId uuid.UUID) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Delete("/v1/subscriptions/%v", orgId),
			http.WithBearer(token.String())),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) ListInvoices(token auth.SignedToken, orgId uuid.UUID, page page.Page) (ret []billing.Invoice, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/subscriptions/%v/invoices", orgId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &ret))
	return
}
