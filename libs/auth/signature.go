package auth

import (
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/errs"
	"github.com/pkg/errors"
)

const (
	SignatureProtocol = "sign/0.1.0"
)

func SignatureUserUri(key crypto.PublicKey) string {
	return fmt.Sprintf("key://%v", key.ID())
}

func SignatureAuthUri(key crypto.PublicKey) string {
	return SignatureAuthUriById(key.ID())
}

func SignatureAuthUriById(key string) string {
	return fmt.Sprintf("signature://%v", key)
}

type SignatureAttempt struct {
	Pub   crypto.PublicKey
	Sig   crypto.Signature
	Nonce crypto.Bytes
	Now   int64
}

func (s SignatureAttempt) Type() string {
	return SignatureProtocol
}

func (s SignatureAttempt) Uri() string {
	return SignatureAuthUriById(s.Pub.ID())
}

func (s SignatureAttempt) Args(raw interface{}) (err error) {
	ptr, ok := raw.(*SignatureAttempt)
	if !ok {
		err = errors.Wrapf(errs.ArgError, "Unexpected authentication arguments [%v]", raw)
		return
	}
	*ptr = s
	return
}

type signatureArgs struct {
	Pub   crypto.PublicKey  `json:"pub,omitempty"`
	Sig   *crypto.Signature `json:"signature"`
	Nonce *crypto.Bytes     `json:"nonce"`
	Now   *int64            `json:"now"`
}

func (s SignatureAttempt) MarshalJSON() (ret []byte, err error) {
	err = enc.Json.EncodeBinary(signatureArgs{&crypto.EncodableKey{s.Pub}, &s.Sig, &s.Nonce, &s.Now}, &ret)
	return
}

func (s *SignatureAttempt) UnmarshalJSON(in []byte) (err error) {
	tmp := crypto.EncodableKey{}
	err = enc.Json.DecodeBinary(in, &signatureArgs{&tmp, &s.Sig, &s.Nonce, &s.Now})
	s.Pub = tmp.PublicKey
	return
}

// internal only (never stored)
type signatureCred struct {
	key    crypto.PublicKey
	signer crypto.Signer
	hash   crypto.Hash
}

func newSignatureCred(key crypto.PublicKey, signer crypto.Signer, hash crypto.Hash) Credential {
	return &signatureCred{key, signer, hash}
}

func (s *signatureCred) Destroy() {
	// nothing to destroy
}

func (s *signatureCred) Uri() string {
	return SignatureAuthUri(s.key)
}

func (s *signatureCred) Auth(rand io.Reader) (ret Attempt, err error) {
	nonce, err := crypto.GenNonce(rand, 32)
	if err != nil {
		return
	}

	now := time.Now().Unix()
	msg := fmt.Sprintf("%v.%v", nonce.Base64(), now)

	sig, err := s.signer.Sign(rand, s.hash, []byte(msg))
	if err != nil {
		return
	}

	ret = SignatureAttempt{s.signer.Public(), sig, nonce, now}
	return
}

func (s *signatureCred) Salt(salt crypto.Salt, size int) (ret crypto.Bytes, err error) {
	sig, err := s.Sign(salt.Hash, salt.Nonce)
	if err != nil {
		return
	}

	ret = salt.Apply(sig, size)
	return
}

func (p *signatureCred) Sign(hash crypto.Hash, nonce []byte) (ret []byte, err error) {

	// Need a stable signature in order to use the signer as an encryption key
	// This means we can't rely on a real random source.  This significantly
	// weakens the signing strength, but this is actually never sent or stored
	// anywhere - it is only ever going to be used as a source for encryption
	// keys - which are guaranteed paired with a random salt.
	sig, err := p.signer.Sign(rand.New(rand.NewSource(1)), hash, nonce)
	if err != nil {
		return
	}

	ret = sig.Data
	return
}

// The data stored on the server .
type SignatureAuth struct {
	typ string
	Pub crypto.PublicKey
}

func NewSignatureAuth(args SignatureAttempt) (Authenticator, error) {
	return SignatureAuth{args.Type(), args.Pub}, nil
}

func (s SignatureAuth) Type() string {
	return s.typ
}

func (s SignatureAuth) Uri() string {
	return SignatureAuthUri(s.Pub)
}

func (s SignatureAuth) Validate(raw Attempt) (err error) {
	if s.Type() != raw.Type() {
		err = errors.Wrapf(errs.ArgError, "Unexpected authentication algorithm [%v]", raw.Type())
		return
	}

	var args SignatureAttempt
	if err = raw.Args(&args); err != nil {
		return
	}

	id := s.Pub.ID()
	if args.Sig.Key != id {
		err = errors.Wrapf(errs.ArgError, "Bad key. Expected [%v]. Got [%v]", id, args.Sig.Key)
		return
	}

	if err = args.Sig.Verify(s.Pub, []byte(fmt.Sprintf("%v.%v", args.Nonce.Base64(), args.Now))); err != nil {
		err = errors.Wrapf(errs.ArgError, "Unable to validate signature [%v]: %v", args.Sig, err)
		return
	}

	return
}

type signingAuth struct {
	Typ *string          `json:"type"`
	Pub crypto.PublicKey `json:"pub"`
}

func (s SignatureAuth) MarshalJSON() (ret []byte, err error) {
	err = enc.Json.EncodeBinary(signingAuth{&s.typ, &crypto.EncodableKey{s.Pub}}, &ret)
	return
}

func (s *SignatureAuth) UnmarshalJSON(in []byte) (err error) {
	tmp := crypto.EncodableKey{}
	err = enc.Json.DecodeBinary(in, &signingAuth{&s.typ, &tmp})
	s.Pub = tmp.PublicKey
	return
}

// Returns a credential closure generated from the signer.  The signer
// is maintained in memory.
func WithSignature(signer crypto.Signer, strength crypto.Strength) Login {
	return func() (Credential, error) {
		return newSignatureCred(signer.Public(), signer, strength.Hash()), nil
	}
}

// Returns a login from a PEM encoded file.  The file must adhere
// to the formatting laid out in crypto#ParsePemFile()
func WithPemFile(file string, fn crypto.PemKeyDecoder) Login {
	return func() (Credential, error) {
		key, err := crypto.ReadPrivateKeyFile(file, fn)
		if err != nil {
			return nil, err
		}
		return newSignatureCred(key.Public(), key, crypto.Moderate.Hash()), nil
	}
}

// Returns a login from a PEM encoded byte array.  The array must adhere
// to the formatting laid out in crypto#ParsePemFile()
func WithPemBytes(raw crypto.Bytes, fn crypto.PemKeyDecoder) Login {
	cop := raw.Copy()
	return func() (Credential, error) {
		key, err := crypto.UnmarshalPemPrivateKey(cop, fn)
		if err != nil {
			return nil, err
		}
		return newSignatureCred(key.Public(), key, crypto.Moderate.Hash()), nil
	}
}
