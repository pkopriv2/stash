package secrets

import (
	"io"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/libs/account"
	"github.com/cott-io/stash/libs/auth"
	"github.com/cott-io/stash/libs/page"
	"github.com/cott-io/stash/libs/policy"
	"github.com/cott-io/stash/libs/secret"
	"github.com/cott-io/stash/sdk/accounts"
	"github.com/cott-io/stash/sdk/policies"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func Search(s session.Session, orgId uuid.UUID, filter secret.Filter, opts ...page.PageOption) (ret []secret.SecretSummary, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, err = s.Options().Secrets().ListSecrets(token, orgId, filter, page.BuildPage(opts...))
	return
}

func RequireById(s session.Session, orgId, id uuid.UUID) (ret secret.SecretSummary, err error) {
	ret, ok, err := LoadById(s, orgId, id)
	if !ok {
		err = errs.Or(err, errors.Wrapf(secret.ErrNoSecret, "No such secret [%v]", id))
	}
	return
}

func LoadById(s session.Session, orgId, id uuid.UUID) (ret secret.SecretSummary, ok bool, err error) {
	all, err := Search(s, orgId, secret.BuildFilter(secret.FilterByIds(id)), page.Limit(1))
	if err != nil || len(all) != 1 {
		return
	}
	ok, ret = true, all[0]
	return
}

func RequireByName(s session.Session, orgId uuid.UUID, name string) (ret secret.SecretSummary, err error) {
	ret, ok, err := LoadByName(s, orgId, name)
	if !ok {
		err = errs.Or(err, errors.Wrapf(secret.ErrNoSecret, "No such secret [%v]", name))
	}
	return
}

func LoadByName(s session.Session, orgId uuid.UUID, name string) (ret secret.SecretSummary, ok bool, err error) {
	all, err := Search(s, orgId, secret.BuildFilter(secret.FilterByName(name)), page.Limit(1))
	if err != nil || len(all) != 1 {
		return
	}
	ok, ret = true, all[0]
	return
}

func ListVersions(s session.Session, orgId, secretId uuid.UUID, opts ...page.PageOption) (ret []secret.Secret, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, err = s.Options().Secrets().ListSecretVersions(token, orgId, secretId, page.BuildPage(opts...))
	return
}

func LoadVersion(s session.Session, orgId, secretId uuid.UUID, version int) (ret secret.Secret, ok bool, err error) {
	token, err := s.FetchToken(auth.WithOrgId(orgId))
	if err != nil {
		return
	}

	ret, ok, err = s.Options().Secrets().LoadSecret(token, orgId, secretId, version)
	return
}

func RequireVersion(s session.Session, orgId, secretId uuid.UUID, version int) (ret secret.Secret, err error) {
	ret, ok, err := LoadVersion(s, orgId, secretId, version)
	if !ok {
		err = errs.Or(err, errors.Wrapf(secret.ErrNoSecret, "No such secret [%v] at version [%v]", secretId, version))
	}
	return
}

func SaveSecret(s session.Session, sec secret.Secret) (err error) {
	if err = secret.VerifyName(sec.Name); err != nil {
		return
	}

	token, err := s.FetchToken(auth.WithOrgId(sec.OrgId))
	if err != nil {
		return
	}

	err = s.Options().Secrets().SaveSecret(token, sec)
	return
}

func RestoreByName(s session.Session, orgId uuid.UUID, name string) (ret secret.Secret, err error) {
	all, err := Search(s, orgId,
		secret.BuildFilter(
			secret.FilterByName(name),
			secret.FilterShowDeleted(true)),
		page.Limit(1))
	if err != nil || len(all) != 1 {
		err = errs.Or(err, errors.Wrapf(secret.ErrNoSecret, "No such secret [%v]", name))
		return
	}
	if !all[0].Deleted {
		err = errors.Wrapf(errs.StateError, "That secret [%v] is not deleted", name)
		return
	}

	ret, err = all[0].Update().SetDeleted(false).Compile()
	if err != nil {
		return
	}

	err = SaveSecret(s, ret)
	return
}

func Create(s session.Session, proto secret.Builder, data io.Reader, o ...func(*StreamOptions)) (ret secret.Secret, err error) {
	init, err := proto.Compile()
	if err != nil {
		return
	}
	opts := BuildStreamOptions(o...)

	policy, err := policies.CreatePolicy(s, init.OrgId, opts.Strength, policy.Sudo)
	if err != nil {
		return ret, err
	}

	ret, err = Write(s, proto.SetPolicy(policy.Id()), data, o...)
	return
}

func Write(s session.Session, proto secret.Builder, data io.Reader, o ...func(*StreamOptions)) (next secret.Secret, err error) {
	priv, err := s.Secret().RecoverKey()
	if err != nil {
		return
	}
	defer priv.Destroy()

	next, err = WriteProxy(s, priv, s.AccountId(), proto, data, o...)
	return
}

func Read(s session.Session, cur secret.Secret, dst io.Writer, o ...func(*StreamOptions)) (err error) {
	if cur.StreamSize == 0 {
		return
	}

	priv, err := s.Secret().RecoverKey()
	if err != nil {
		return
	}
	defer priv.Destroy()

	err = ReadProxy(s, priv, s.AccountId(), cur, dst, o...)
	return
}

//func CreateProxy(s session.Session, memberKey crypto.PrivateKey, memberId uuid.UUID, memberType policy.Type, proto secret.Builder, data io.Reader, o ...func(*StreamOptions)) (ret secret.Secret, err error) {
//init, err := proto.Compile()
//if err != nil {
//return
//}
//opts := BuildStreamOptions(o...)

//policy, err := policies.CreateProxyPolicy(s, init.OrgId, memberId, memberKey.Public(), memberType, opts.Strength)
//if err != nil {
//return
//}

//ret, err = WriteProxy(s, memberKey, memberId, proto.SetPolicy(policy.Id()), data, o...)
//return
//}

func WriteProxy(s session.Session, memberKey crypto.PrivateKey, memberId uuid.UUID, proto secret.Builder, data io.Reader, o ...func(*StreamOptions)) (next secret.Secret, err error) {
	cur, err := proto.Compile()
	if err != nil {
		return
	}

	lock, err := policies.RequirePolicyLock(s, cur.OrgId, cur.PolicyId, memberId)
	if err != nil {
		return
	}

	pass, err := lock.RecoverSecret(crypto.Rand, memberKey)
	if err != nil {
		return
	}
	defer pass.Destroy()

	salt, err := lock.Strength().GenSalt(crypto.Rand)
	if err != nil {
		return
	}

	streamId := uuid.NewV1()

	writer := NewBlockWriter(
		crypto.Rand, cur.OrgId, streamId, salt, pass, lock.Strength().Cipher())

	token, err := s.FetchToken(auth.WithOrgId(cur.OrgId))
	if err != nil {
		return
	}

	hash, size, err := Upload(s.Options().Secrets(), token, writer, data, o...)
	if err != nil {
		return
	}

	priv, err := s.Secret().RecoverKey()
	if err != nil {
		return
	}
	defer priv.Destroy()

	sig, err := priv.Sign(crypto.Rand, lock.Strength().Hash(), hash)
	if err != nil {
		return
	}

	next, err = proto.
		SetStream(streamId, size).
		SetAuthor(s.AccountId(), sig).
		SetSalt(salt).
		Compile()
	if err != nil {
		return
	}

	err = SaveSecret(s, next)
	return
}

func ReadProxy(s session.Session, memberKey crypto.PrivateKey, memberId uuid.UUID, cur secret.Secret, dst io.Writer, o ...func(*StreamOptions)) (err error) {
	if cur.StreamSize == 0 {
		return
	}

	pub, err := accounts.RequirePublicKey(s, cur.AuthorId)
	if err != nil {
		err = errors.Wrapf(err, "Unable to obtain key for author [%v]", cur.AuthorId)
		return
	}

	lock, err := policies.RequirePolicyLock(s, cur.OrgId, cur.PolicyId, memberId)
	if err != nil {
		err = errors.Wrapf(err, "Unable to obtain lock for [%v]", cur.Name)
		return
	}

	pass, err := lock.RecoverSecret(crypto.Rand, memberKey)
	if err != nil {
		err = errors.Wrapf(err, "Could not recover decryption key for [%v]", cur.Name)
		return
	}
	defer pass.Destroy()

	token, err := s.FetchToken(auth.WithOrgId(cur.OrgId))
	if err != nil {
		return
	}

	reader := NewBlockReader(cur.Salt, pass, lock.Strength().Cipher())
	hash, err := Download(s.Options().Secrets(), token, cur, reader, dst, o...)
	if err != nil {
		return
	}

	err = cur.AuthorSig.Verify(pub, hash)
	return
}

func CollectAuthors(s session.Session, all []secret.SecretSummary) (ret map[uuid.UUID]auth.Identity, err error) {
	var arr []uuid.UUID
	for _, s := range all {
		arr = append(arr, s.AuthorId)
	}

	tmp, err := accounts.ListIdentitiesByAccountIds(s, arr)
	if err != nil {
		return
	}

	ret = make(map[uuid.UUID]auth.Identity)
	for id, info := range tmp {
		ret[id] = account.LookupDisplay(info).Id
	}
	return
}
