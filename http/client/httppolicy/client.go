package httppolicy

import (
	"github.com/cott-io/stash/lang/enc"
	http "github.com/cott-io/stash/lang/http/client"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	uuid "github.com/satori/go.uuid"
)

// ** CLIENT IMPLEMENTATIONS ** //

type HttpClient struct {
	Raw http.Client
	Reg enc.Registry
}

func NewClient(raw http.Client, reg enc.Registry) policy.Transport {
	return &HttpClient{raw, reg}
}

func (h *HttpClient) SaveGroup(token auth.SignedToken, group policy.Group) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/orgs/%v/groups/%v", group.OrgId, group.Id),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, group)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) ListGroups(token auth.SignedToken, orgId uuid.UUID, filter policy.GroupFilter, page page.Page) (ret []policy.GroupInfo, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/groups_list", orgId),
			http.WithBearer(token.String()),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithStruct(enc.Json, filter)),
		http.ExpectStruct(h.Reg, &ret))
	return
}

type SavePolicyRequest struct {
	Policy policy.Policy       `json:"policy"`
	Member policy.PolicyMember `json:"policy_member"`
}

func (h *HttpClient) CreatePolicy(token auth.SignedToken, policy policy.Policy, member policy.PolicyMember) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/policies", policy.OrgId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, SavePolicyRequest{policy, member})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) UpdatePolicy(token auth.SignedToken, policy policy.Policy) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/orgs/%v/policies/%v", policy.OrgId, policy.Id),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, policy)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) SavePolicyMember(token auth.SignedToken, member policy.PolicyMember) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Put("/v1/orgs/%v/policies/%v/members/%v", member.OrgId, member.PolicyId, member.MemberId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, member)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadPolicyMember(token auth.SignedToken, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyMember, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/policies/%v/members/%v", orgId, policyId, memberId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) ListPolicyMembers(token auth.SignedToken, orgId, policyId uuid.UUID, page page.Page) (ret []policy.PolicyMemberInfo, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/policies/%v/members", orgId, policyId),
			http.WithBearer(token.String()),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit)),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) LoadPolicy(token auth.SignedToken, orgId, policyId uuid.UUID) (ret policy.Policy, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/policies/%v", orgId, policyId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) LoadPolicyLock(token auth.SignedToken, orgId, policyId, memberId uuid.UUID) (ret policy.PolicyLock, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/policies/%v/lock", orgId, policyId),
			http.WithBearer(token.String()),
			http.WithQueryParam("member_id", memberId)),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}
