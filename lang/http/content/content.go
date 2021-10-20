package content

import (
	"io"

	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/http/headers"
	"github.com/cott-io/stash/lang/mime"
	"github.com/pkg/errors"
)

var (
	ErrHttp = errors.New("Http:Error")
)

type Message interface {
	io.Closer
	ReadHeader(string, *string) bool
	ReadBody(*[]byte) error
}

func ParseStruct(res Message, reg enc.Registry, ptr interface{}) (ok bool, err error) {
	ct := headers.ReadHeader(res, headers.ContentType, mime.Json)
	defer res.Close()

	ok, dec := reg.FindByMime(ct)
	if !ok {
		err = errors.Wrapf(errs.ArgError, "Unsupported content type [%v]", ct)
		return
	}

	var body []byte
	if err = res.ReadBody(&body); err != nil || body == nil || len(body) == 0 {
		return
	}

	if err = dec.DecodeBinary(body, ptr); err != nil {
		err = errors.Wrapf(err, "Error reading body")
	}

	ok = true
	return
}

func RequireStruct(res Message, reg enc.Registry, ptr interface{}) (err error) {
	ok, err := ParseStruct(res, reg, ptr)
	if err != nil {
		return
	}
	if !ok {
		err = errors.Wrapf(errs.StateError, "Missing required body")
	}
	return
}

func ParseString(res Message, ptr *string) (err error) {
	var msg []byte
	if err = res.ReadBody(&msg); err != nil {
		return
	}
	*ptr = string(msg)
	return
}

func ParseError(res Message, ptr *error) (err error) {
	var msg string
	if err = ParseString(res, &msg); err != nil {
		return
	}
	*ptr = errors.New(msg)
	return
}

func ReadError(res Message) (err error) {
	if res == nil {
		return
	}

	var msg string
	if err = ParseString(res, &msg); err != nil {
		if err == io.EOF {
			err = nil
		}
		return
	}
	err = errors.Wrap(ErrHttp, msg)
	return
}
