package httpaccount

import (
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	http "github.com/cott-io/stash/lang/http/client"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	uuid "github.com/satori/go.uuid"
)

type RegisterRequest struct {
	Id      auth.Identity         `json:"identity"`
	Opts    auth.IdentityOptions  `json:"identity_opts"`
	Attempt auth.EncodableAttempt `json:"attempt"`
	Secret  account.Secret        `json:"secret"`
	Shard   account.LoginShard    `json:"shard"`
}

type AuthRequest struct {
	Id      auth.Identity         `json:"identity"`
	Attempt auth.EncodableAttempt `json:"attempt"`
	Opts    auth.AuthOptions      `json:"opts,omitempty"`
}

type IdentityRegisterRequest struct {
	AcctId uuid.UUID            `json:"account_id"`
	Id     auth.Identity        `json:"identity"`
	Opts   auth.IdentityOptions `json:"opts,omitempty"`
}

type IdentityVerifyRequest struct {
	Id      auth.Identity         `json:"identity"`
	Attempt auth.EncodableAttempt `json:"attempt"`
}

type LoginRegisterRequest struct {
	Attempt auth.EncodableAttempt `json:"attempt"`
	Shard   account.LoginShard    `json:"shard"`
}

type ListIdentitiesRequest struct {
	Ids []uuid.UUID
}

type HttpClient struct {
	Raw http.Client
	Reg enc.Registry
}

func NewClient(raw http.Client, reg enc.Registry) account.Transport {
	return &HttpClient{raw, reg}
}

func (h *HttpClient) Register(id auth.Identity, attempt auth.Attempt, secret account.Secret, shard account.LoginShard, opts auth.IdentityOptions) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/accounts"),
			http.WithStruct(enc.Json,
				RegisterRequest{id, opts, auth.EncodableAttempt{attempt}, secret, shard})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) Authenticate(id auth.Identity, attempt auth.Attempt, opts auth.AuthOptions) (ret auth.SignedToken, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/auth"),
			http.WithStruct(enc.Json,
				AuthRequest{id, auth.EncodableAttempt{attempt}, opts})),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) LoadSecretAndShard(token auth.SignedToken, acctId uuid.UUID, uri string, version int) (ret account.SecretAndShard, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/accounts/%v/secret/%v", acctId, uri),
			http.WithQueryParam("version", version),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) IdentityRegister(token auth.SignedToken, acctId uuid.UUID, id auth.Identity, opts auth.IdentityOptions) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/identities"),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json,
				IdentityRegisterRequest{acctId, id, opts})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) IdentityVerify(id auth.Identity, proof auth.Attempt) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/verify"),
			http.WithStruct(enc.Json,
				IdentityVerifyRequest{id, auth.EncodableAttempt{proof}})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadIdentity(token auth.SignedToken, id auth.Identity) (ret account.Identity, ok bool, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/identities/%v", id),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &ret))
	return
}

func (h *HttpClient) ListIdentitiesByAccountId(token auth.SignedToken, acctId uuid.UUID, page page.Page) (ret []account.Identity, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/identities"),
			http.WithQueryParam("account_id", acctId),
			http.WithQueryParam("offset", page.Offset),
			http.WithQueryParam("limit", page.Limit),
			http.WithBearer(token.String())),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) ListIdentitiesByAccountIds(token auth.SignedToken, acctIds []uuid.UUID) (ret map[uuid.UUID][]account.Identity, err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/identities_list"),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json, ListIdentitiesRequest{acctIds})),
		http.ExpectStruct(h.Reg, &ret))
	return
}

func (h *HttpClient) IdentityDelete(token auth.SignedToken, id auth.Identity) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Delete("/v1/identities/%v", id),
			http.WithBearer(token.String())),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoginRegister(token auth.SignedToken, acctId uuid.UUID, attempt auth.Attempt, shard account.LoginShard) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Post("/v1/accounts/%v/logins", acctId),
			http.WithBearer(token.String()),
			http.WithStruct(enc.Json,
				LoginRegisterRequest{auth.EncodableAttempt{attempt}, shard})),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoginDelete(token auth.SignedToken, acctId uuid.UUID, uri string) (err error) {
	err = h.Raw.Call(
		http.BuildRequest(
			http.Delete("/v1/accounts/%v/logins/%v", acctId, uri),
			http.WithBearer(token.String())),
		http.ExpectCode(204))
	return
}

func (h *HttpClient) LoadPublicKey(token auth.SignedToken, acctId uuid.UUID) (ret crypto.PublicKey, ok bool, err error) {
	var key crypto.EncodableKey
	err = h.Raw.Call(
		http.BuildRequest(
			http.Get("/v1/accounts/%v/key", acctId),
			http.WithBearer(token.String())),
		http.MaybeExpectStruct(h.Reg, &ok, &key))
	ret = key.PublicKey
	return
}
