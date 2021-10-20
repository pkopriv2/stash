package session

import (
	"fmt"
	"time"

	"github.com/cott-io/stash/http/client/httpaccount"
	"github.com/cott-io/stash/http/client/httporg"
	"github.com/cott-io/stash/http/client/httppolicy"
	"github.com/cott-io/stash/http/client/httpsecret"
	"github.com/cott-io/stash/lang/config"
	"github.com/cott-io/stash/lang/context"
	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/env"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/http/client"
	"github.com/cott-io/stash/lang/path"
	"github.com/cott-io/stash/lang/secret"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/org"
	"github.com/cott-io/stash/libs/policy"
	secrt "github.com/cott-io/stash/libs/secret"
	"github.com/denisbrodbeck/machineid"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	DefaultKeyFile  = "~/.stash/key.pem"
	DefaultTTL      = 30 * time.Minute
	DefaultStrength = crypto.Moderate
	DefaultAddr     = ":8080"
)

func getSessionKey(c config.Config) (ret string, err error) {
	err = c.GetOrDefault("stash.session.key", config.String, &ret, DefaultKeyFile)
	return
}

func getSessionOrgId(c config.Config) (ret uuid.UUID, err error) {
	err = c.GetOrDefault("stash.session.org", config.UUID, &ret, uuid.UUID{})
	return
}

func getSessionAddr(c config.Config) (ret string, err error) {
	err = c.GetOrDefault("stash.session.addr", config.String, &ret, DefaultAddr)
	return
}

func getSessionStrength(c config.Config) (ret crypto.Strength, err error) {
	err = c.GetOrDefault("stash.session.strength", config.Strength, &ret, DefaultStrength)
	return
}

func getSessionClient(c config.Config) (ret client.Client, err error) {
	addr, err := getSessionAddr(c)
	if err != nil {
		return
	}

	ret = client.NewDefaultClient(addr)
	return
}

type Option func(*Options) error

type Options struct {
	Strength crypto.Strength
	Config   config.Config
	Cache    Cache
	OrgId    uuid.UUID
	Client   client.Client
}

var emptyId = uuid.UUID{}

func (o Options) RequireOrgId() (ret uuid.UUID, err error) {
	if o.OrgId == emptyId {
		err = errors.Wrapf(errs.StateError, "Missing required org id")
		return
	}

	ret = o.OrgId
	return
}

func (o Options) Accounts() account.Transport {
	return httpaccount.NewClient(o.Client, enc.DefaultRegistry)
}

func (o Options) Orgs() org.Transport {
	return httporg.NewClient(o.Client, enc.DefaultRegistry)
}

func (o Options) Policies() policy.Transport {
	return httppolicy.NewClient(o.Client, enc.DefaultRegistry)
}

func (o Options) Secrets() secrt.Transport {
	return httpsecret.NewClient(o.Client, enc.DefaultRegistry)
}

func buildOptions(opts ...Option) (ret Options, err error) {
	ret = Options{
		Strength: crypto.Moderate,
		Config:   config.NewConfig(),
		Cache:    NewLRUCache(10),
		OrgId:    uuid.UUID{}}
	for _, fn := range opts {
		if err := fn(&ret); err != nil {
			return ret, err
		}
	}
	if ret.Client == nil {
		err = errors.Wrapf(errs.StateError, "Missing http client")
	}
	return
}

func WithCache(c Cache) Option {
	return func(s *Options) (err error) {
		s.Cache = c
		return
	}
}

func WithStrength(strength crypto.Strength) Option {
	return func(s *Options) (err error) {
		s.Strength = strength
		return
	}
}

func WithConfig(c config.Config) Option {
	return func(o *Options) (err error) {
		o.Config = c
		if o.Strength, err = getSessionStrength(c); err != nil {
			return
		}
		if o.Client, err = getSessionClient(c); err != nil {
			return
		}
		if o.OrgId, err = getSessionOrgId(c); err != nil {
			return
		}
		return
	}
}

func WithClient(client client.Client) Option {
	return func(s *Options) (err error) {
		s.Client = client
		return
	}
}

type Session interface {
	env.Environment

	// session options
	Options() Options

	// The unique identitier of the session owner
	AccountId() uuid.UUID

	// The login identity of the session owner
	LoginId() auth.Identity

	// The session secret containing the credentials
	Secret() *SessionSecret

	// Fetches a signed token.
	FetchToken(...auth.AuthOption) (auth.SignedToken, error)

	// A local cache (encrypted if durable)
	Cache() Cache
}

type session struct {
	env.Environment
	ctx    context.Context
	ctrl   context.Control
	log    context.Logger
	secret *SessionSecret
	cache  Cache
	opts   Options
}

func NewDefaultSession(ctx context.Context, conf config.Config) (ret Session, err error) {
	file, err := getSessionKey(conf)
	if err != nil {
		return
	}

	file, err = path.Expand(file)
	if err != nil {
		return
	}

	strength, err := getSessionStrength(conf)
	if err != nil {
		return
	}

	key, err := crypto.ReadPrivateKeyFile(file, crypto.PKCS1Decoder)
	if err != nil {
		return
	}

	return Authenticate(ctx, auth.ByKey(key.Public()), auth.WithSignature(key, strength), WithConfig(conf))
}

func newSession(env env.Environment, id auth.Identity, login auth.Login, secret account.Secret, shard account.LoginShard, opts Options) (ret Session, err error) {
	ctx := env.Context().Sub("Session")
	ret = &session{
		env,
		ctx,
		ctx.Control(),
		ctx.Logger(),
		newSessionSecret(id, login, secret, shard, opts.Strength),
		opts.Cache,
		opts,
	}
	return
}

func (s *session) Options() Options {
	return s.opts
}

func (s *session) Close() error {
	return s.ctx.Close()
}

func (s *session) Context() context.Context {
	return s.ctx
}

func (s *session) Control() context.Control {
	return s.ctrl
}

func (s *session) Logger() context.Logger {
	return s.log
}

func (s *session) Cache() Cache {
	return s.cache
}

func (s *session) AccountId() uuid.UUID {
	return s.secret.AccountId()
}

func (s *session) LoginId() auth.Identity {
	return s.secret.Identity()
}

func (s *session) Strength() crypto.Strength {
	return s.opts.Strength
}

func (s *session) Secret() *SessionSecret {
	return s.secret
}

func (s *session) FetchToken(fns ...auth.AuthOption) (ret auth.SignedToken, err error) {
	deviceId, err := machineid.ProtectedID("stash")
	if err != nil {
		return auth.SignedToken{}, errors.Wrap(err, "Unable to generate device id")
	}

	opts := auth.BuildOptions(
		append(fns,
			auth.WithDeviceId(deviceId),
			auth.WithTimeout(s.opts.Strength.TokenTimeout()))...)

	key := fmt.Sprintf("%v.%v", s.LoginId(), opts.OrgId)
	s.Logger().Debug("Attempting to retrieve token from cache [%v]", key)

	ok, err := s.Cache().Get(key, &ret)
	if err != nil || (ok && ret.Expires().After(time.Now())) {
		return
	}

	attmpt, err := s.Secret().AuthAttempt()
	if err != nil {
		return
	}

	ret, err = s.opts.Accounts().Authenticate(s.LoginId(), attmpt, opts)
	if err != nil {
		return
	}

	err = s.Cache().Set(key, ret, opts.Expires)
	return
}

//func (t *session) Identities() (ret []account.Identity, err error) {
//err = Call(t.ApiClient(),
//idListCall(
//t.AcctId(),
//util.BuildPagingOptions(
//page.PageBeg(0),
//page.PageMax(16)),
//&ret))
//return
//}

// A session secrets safely manages access to the underlying credentials
// and secrets.
type SessionSecret struct {

	// the account uri
	identity auth.Identity

	// the login credentials closure. (may be some io device)
	login auth.Login

	// the session owner's secret. (encrypted and safe to store in memory)
	secret account.Secret

	// the session owner's login shard.  shard + secret -> secret key
	shard account.LoginShard

	// the sessions strength (used for *most* crypto functions)
	strength crypto.Strength
}

func newSessionSecret(id auth.Identity, l auth.Login, m account.Secret, sh account.LoginShard, s crypto.Strength) *SessionSecret {
	return &SessionSecret{id, l, m, sh, s}
}

func (s *SessionSecret) AccountId() uuid.UUID {
	return s.secret.AccountId
}

func (s *SessionSecret) Identity() auth.Identity {
	return s.identity
}

func (s *SessionSecret) PublicKey() crypto.PublicKey {
	return s.secret.Chain.Key.Pub
}

// Returns a new authentication attempt using the underlying credentials
func (s *SessionSecret) AuthAttempt() (ret auth.Attempt, err error) {
	cred, err := auth.ExtractCreds(s.login)
	if err != nil {
		return
	}
	defer cred.Destroy()
	return cred.Auth(crypto.Rand)
}

// Returns the session owner's account secret
func (s *SessionSecret) DeriveSecret() (ret secret.Secret, err error) {
	creds, err := auth.ExtractCreds(s.login)
	if err != nil {
		return
	}
	defer creds.Destroy()
	return s.secret.DeriveSecret(creds, s.shard)
}

// Returns the signing key associated with this session. Should be promptly destroyed.
func (s *SessionSecret) DecryptKey(secret secret.Secret) (crypto.PrivateKey, error) {
	return s.secret.UnlockKey(secret)
}

// Returns the account's private key. Should be promptly destroyed.
func (s *SessionSecret) RecoverKey() (crypto.PrivateKey, error) {
	secret, err := s.DeriveSecret()
	if err != nil {
		return nil, err
	}
	defer secret.Destroy()
	return s.DecryptKey(secret)
}

func (s *SessionSecret) SaltWithSecret(salt crypto.Salt, size int) (crypto.Bytes, error) {
	secret, err := s.DeriveSecret()
	if err != nil {
		return nil, err
	}
	defer secret.Destroy()

	raw, err := s.hashSecret(secret)
	if err != nil {
		return nil, err
	}

	return salt.Apply(raw, size), nil
}

func (s *SessionSecret) EncryptWithSecret(msg []byte) (crypto.SaltedCipherText, error) {
	secret, err := s.DeriveSecret()
	if err != nil {
		return crypto.SaltedCipherText{}, err
	}
	defer secret.Destroy()

	key, err := s.hashSecret(secret)
	if err != nil {
		return crypto.SaltedCipherText{}, err
	}

	return s.strength.SaltAndEncrypt(crypto.Rand, key, msg)
}

func (s *SessionSecret) DecryptWithSecret(msg crypto.SaltedCipherText) ([]byte, error) {
	secret, err := s.DeriveSecret()
	if err != nil {
		return nil, err
	}
	defer secret.Destroy()

	key, err := s.hashSecret(secret)
	if err != nil {
		return nil, err
	}

	return msg.Decrypt(key)
}

// Generates a new account shard that may only be derived with the given credential.
func (s *SessionSecret) NewLoginShard(cred auth.Credential) (ret account.LoginShard, err error) {
	secret, err := s.DeriveSecret()
	if err != nil {
		return
	}
	defer secret.Destroy()
	ret, err = s.secret.NewShard(crypto.Rand, secret, cred)
	return
}

// Returns the personal encryption seed of this subscription.
func (s *SessionSecret) hashSecret(secret secret.Secret) ([]byte, error) {
	return secret.Hash(s.secret.Chain.Hash)
}
