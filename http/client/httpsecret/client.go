package httpsecret

import (
	"github.com/cott-io/stash/lang/enc"
	http "github.com/cott-io/stash/lang/http/client"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/secret"
	uuid "github.com/satori/go.uuid"
)

type HttpClient struct {
	Raw http.Client
	Reg enc.Registry
}

func NewClient(raw http.Client, reg enc.Registry) secret.Transport {
	return &HttpClient{raw, reg}
}

func (h *HttpClient) SaveSecret(token auth.SignedToken, sec secret.Secret) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/secrets", sec.OrgId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, sec)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadSecret(token auth.SignedToken, orgId, secretId uuid.UUID, version int) (sec secret.Secret, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/secrets/%v", orgId, secretId),
			http.WithBearer(token.String()),
			http.WithQueryParam("version", version)),
		http.MaybeExpectStruct(h.Reg, &ok, &sec))
	return
}

type ListSecretRequest struct {
	Filter secret.Filter `json:"filter"`
}

func (h *HttpClient) ListSecrets(token auth.SignedToken, orgId uuid.UUID, filter secret.Filter, page page.Page) (ret []secret.SecretSummary, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/secrets_list", orgId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, filter)),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) ListSecretVersions(token auth.SignedToken, orgId, secId uuid.UUID, page page.Page) (ret []secret.Secret, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/secrets/%v/versions", orgId, secId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) SaveBlocks(token auth.SignedToken, blocks ...secret.Block) (err error) {
	if len(blocks) == 0 {
		return
	}

	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/orgs/%v/blocks", blocks[0].OrgId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, blocks)),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadBlocks(token auth.SignedToken, orgId, secId uuid.UUID, version int, page page.Page) (ret []secret.Block, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/orgs/%v/blocks/%v", orgId, secId),
			http.WithBearer(token.String()),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithQueryParam("version", version)),
		http.ExpectStruct(h.Reg, &ret))
	return
}
