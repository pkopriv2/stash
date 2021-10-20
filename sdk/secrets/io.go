package secrets

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/cott-io/stash/lang/enc"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/path"
	"github.com/cott-io/stash/lang/ref"
	"github.com/cott-io/stash/libs/secret"
	"github.com/cott-io/stash/sdk/session"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

const (
	Latest = -1
)

const (
	StdOut = "-"
	StdIn  = "-"
)

type SrcOptions struct {
	Update func(int)
}

// A source is a source of data.
type Src interface {
	Read(io.Writer) error
}

type DstOptions struct {
	Desc     string
	Cmmt     string
	Validate func(sec secret.Secret, cur []byte) error
}

// A destination is a destination for data
type Dst interface {
	Write(io.Reader, ...func(*DstOptions)) error
}

// An IO contains a source and a destination
type IO interface {
	Src
	Dst
}

func parseVersion(name string) (ver int, err error) {
	if !strings.Contains(name, ":") {
		ver = Latest
		return
	}

	ver, err = strconv.Atoi(strings.SplitN(name, ":", 2)[1])
	return
}

func OpenSecret(s session.Session, orgId uuid.UUID, str string) (src SecretIO) {
	src = SecretIO{orgId, ref.Pointer(str), s}
	return
}

func OpenNative(str string) (src IO) {
	if str == StdIn {
		src = StdIO{os.Stdin, os.Stdout}
		return
	}

	if strings.HasPrefix(str, "file://") {
		src = FileIO{strings.TrimPrefix(str, "file://")}
		return
	}

	if strings.HasPrefix(str, "@") {
		src = FileIO{strings.TrimPrefix(str, "@")}
		return
	}

	src = LiteralIO{str}
	return

}

type LiteralIO struct {
	val string
}

func (s LiteralIO) Read(w io.Writer) (err error) {
	_, err = io.Copy(w, bytes.NewBuffer([]byte(s.val)))
	return
}

func (s LiteralIO) Write(r io.Reader, o ...func(*DstOptions)) (err error) {
	err = errors.New("Literals only allowed as sources")
	return
}

type StdIO struct {
	R io.Reader
	W io.Writer
}

func (s StdIO) Read(w io.Writer) (err error) {
	_, err = io.Copy(w, s.R)
	return
}

func (s StdIO) Write(r io.Reader, o ...func(*DstOptions)) (err error) {
	_, err = io.Copy(s.W, r)
	return
}

type FileIO struct {
	path string
}

func (s FileIO) Read(w io.Writer) (err error) {
	path, err := path.Expand(s.path)
	if err != nil {
		return
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, err = io.Copy(w, file)
	return
}

func (s FileIO) Write(r io.Reader, o ...func(*DstOptions)) (err error) {
	path, err := path.Expand(s.path)
	if err != nil {
		return
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	_, err = io.Copy(file, r)
	return
}

type SecretIO struct {
	OrgId uuid.UUID
	Addr  ref.Pointer
	Conn  session.Session
}

func (s SecretIO) getName() (ret string) {
	doc := s.Addr.Document()
	if !strings.Contains(doc, ":") {
		return doc
	} else {
		return strings.SplitN(doc, ":", 2)[0]
	}
}

func (s SecretIO) TryLoad() (sec secret.Secret, ok bool, err error) {
	tmp, ok, err := LoadByName(s.Conn, s.OrgId, s.getName())
	if err != nil || !ok {
		return
	}
	sec = tmp.Secret
	return
}

func (s SecretIO) MustLoad() (sec secret.Secret, err error) {
	tmp, err := RequireByName(s.Conn, s.OrgId, s.getName())
	if err != nil {
		return
	}
	sec = tmp.Secret
	return
}

func (s SecretIO) Read(w io.Writer) (err error) {
	sec, err := s.MustLoad()
	if err != nil {
		return
	}

	ver, err := parseVersion(s.Addr.Document())
	if err != nil {
		return
	}

	if ver >= 0 {
		sec, err = RequireVersion(s.Conn, s.OrgId, sec.Id, ver)
		if err != nil {
			return
		}
	}

	if s.Addr.Ref().Empty() {
		err = Read(s.Conn, sec, w)
		return
	}

	ok, dec := enc.DefaultRegistry.FindByMime(s.Addr.Mime())
	if !ok {
		dec = enc.Yaml
	}

	buf := &bytes.Buffer{}
	if err = Read(s.Conn, sec, buf); err != nil {
		err = errors.Wrapf(err, "Unable to read [%v]", s.Addr.Document())
		return
	}

	obj, err := ref.ReadObject(dec, buf.Bytes())
	if err != nil {
		err = errors.Wrapf(err, "Unable to read [%v]", s.Addr)
		return
	}

	val, ok := obj.GetRaw(s.Addr.Ref())
	if !ok {
		err = errors.Wrapf(secret.ErrNoSecret, "No such value [%v]", s.Addr.Ref())
		return
	}

	var out []byte
	switch t := val.(type) {
	default:
		err = dec.EncodeBinary(t, &out)
	case string:
		out = []byte(t)
	}

	_, err = w.Write(out)
	return
}

func (s SecretIO) Write(r io.Reader, o ...func(*DstOptions)) (err error) {
	opts := DstOptions{}
	for _, fn := range o {
		fn(&opts)
	}

	sec, ok, err := LoadByName(s.Conn, s.OrgId, s.Addr.Document())
	if err != nil {
		return
	}

	var proto secret.Builder
	if !ok {
		proto = secret.NewSecret().
			SetOrg(s.OrgId).
			SetName(s.Addr.Document())
	} else {
		proto = sec.Update()
	}
	if opts.Desc != "" {
		proto = proto.SetDesc(opts.Desc)
	}
	if opts.Cmmt != "" {
		proto = proto.SetComment(opts.Cmmt)
	}

	if s.Addr.Ref().Empty() {
		if !ok {
			_, err = Create(s.Conn, proto, r)
		} else {
			_, err = Write(s.Conn, proto, r)
		}
		return
	}

	ok, encoder := enc.DefaultRegistry.FindByMime(s.Addr.Mime())
	if !ok {
		err = errors.Wrapf(errs.ArgError, "No such encoder for mime [%v]", s.Addr.Mime())
		return
	}

	cur := ref.Object(ref.NewEmptyMap())
	if ok {
		buf := &bytes.Buffer{}
		if err := Read(s.Conn, sec.Secret, buf); err != nil {
			return err
		}

		cur, err = ref.ReadObject(encoder, buf.Bytes())
		if err != nil {
			return err
		}
	}

	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return
	}

	if err = cur.Set(s.Addr.Ref(), string(raw)); err != nil {
		return
	}

	next, err := enc.Encode(encoder, cur)
	if err != nil {
		return
	}

	if ok {
		_, err = Write(s.Conn, proto, bytes.NewBuffer(next))
	} else {
		_, err = Create(s.Conn, proto, bytes.NewBuffer(next))
	}
	return
}
