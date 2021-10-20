package auth

import (
	"github.com/cott-io/stash/lang/enc"
)

type EncodableAttempt struct {
	Attempt
}

func (e *EncodableAttempt) UnmarshalJSON(in []byte) error {
	return enc.ReadIface(enc.Json, in, enc.Impls{
		PasswordProtocol:  &PasswordAttempt{},
		SignatureProtocol: &SignatureAttempt{},
	}, &e.Attempt)
}

func (e EncodableAttempt) MarshalJSON() ([]byte, error) {
	return enc.WriteIface(enc.Json, e.Attempt.Type(), e.Attempt)
}

func EncodeAttempt(enc enc.Encoder, a Attempt) (ret []byte, err error) {
	err = enc.EncodeBinary(&EncodableAttempt{a}, &ret)
	return
}

func DecodeAttempt(enc enc.Decoder, in []byte) (ret Attempt, err error) {
	tmp := &EncodableAttempt{}
	err = enc.DecodeBinary(in, &tmp)
	ret = tmp.Attempt
	return
}

type EncodableAuth struct {
	Authenticator
}

func (e *EncodableAuth) UnmarshalJSON(in []byte) error {
	return enc.ReadIface(enc.Json, in, enc.Impls{
		PasswordProtocol:  &PasswordAuth{},
		SignatureProtocol: &SignatureAuth{},
	}, &e.Authenticator)
}

func (e EncodableAuth) MarshalJSON() ([]byte, error) {
	return enc.WriteIface(enc.Json, e.Authenticator.Type(), e.Authenticator)
}

func EncodeAuth(enc enc.Encoder, a Authenticator) (ret []byte, err error) {
	err = enc.EncodeBinary(&EncodableAuth{a}, &ret)
	return
}

func DecodeAuth(enc enc.Decoder, in []byte) (ret Authenticator, err error) {
	tmp := &EncodableAuth{}
	err = enc.DecodeBinary(in, &tmp)
	ret = tmp.Authenticator
	return
}
