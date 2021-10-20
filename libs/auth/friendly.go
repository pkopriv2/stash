package auth

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cott-io/stash/lang/crypto"
	"github.com/cott-io/stash/lang/errs"
	"github.com/cott-io/stash/lang/path"
	"github.com/pkg/errors"
)

// ** IDENTITY MATCHING ** //
//
// This implements the core identity friendly format specification.
// This is an incredibly important component because it allows humans
// an easy way to identify resources that is hopefully very natural.
//
// Currently.  Identifiers take the following forms:
//
//  * Email: user@example.com
//  * Phone: x-xxx-xxx-xxxx
//  * Pem:   key.pem
//
var (
	emailMatch = regexp.MustCompile("^[^@]+@[^@]+\\.[^@]+$")
	phoneMatch = regexp.MustCompile("^[0-9]{3}-[0-9]{3}-[0-9]{4}$")
	userMatch  = regexp.MustCompile("^@[^@]+$")
	pemMatch   = regexp.MustCompile("\\.pem$")
	keyMatch   = regexp.MustCompile("=$")
	wordMatch  = regexp.MustCompile("^[a-zA-Z0-9\\-\\_\\.]+[a-zA-Z0-9]$")
)

func IsEmail(str string) bool {
	return emailMatch.MatchString(str)
}

func IsPhone(str string) bool {
	return phoneMatch.MatchString(str)
}

func IsPem(str string) bool {
	return pemMatch.MatchString(str)
}

func IsKey(str string) bool {
	return keyMatch.MatchString(str)
}

func IsUser(str string) bool {
	return userMatch.MatchString(str)
}

func FormatFriendlyIdentity(id Identity) string {
	switch id.Protocol() {
	default:
		return id.Uri()
	case Email, Phone, UUID, Key, Pem:
		return id.Value()
	case User:
		return fmt.Sprintf("@%v", id.Value())
	}
}

func ParseFriendlyIdentity(str string) (ret Identity, err error) {
	// ORDER MATTERS HERE!
	if IsPem(str) {
		return ByPemFile(str), nil
	}
	if IsKey(str) {
		return ByKeyId(str), nil
	}
	if IsPhone(str) {
		return ByPhone(str), nil
	}
	if IsUser(str) {
		name, err := ParseUserName(str)
		if err != nil {
			return ret, err
		}
		return ByUser(name), nil
	}
	if IsEmail(str) {
		return ByEmail(str), nil
	}

	return ByStdUri(str)
}

func ParseUserName(str string) (name string, err error) {
	if str == "" {
		err = errors.Wrapf(errs.ArgError, "Empty user name")
		return
	}

	if !strings.HasPrefix(str, "@") || !IsUser(str) {
		err = errors.Wrapf(errs.ArgError, "Invalid user [%v]. Must be of form @<name>", str)
		return
	}
	name = string([]rune(str)[1:])
	return
}

// Tries to load the identity, even if it comes from a pem file.
func LoadIdentity(str string) (ret Identity, err error) {
	ret, err = ParseFriendlyIdentity(str)
	if err != nil {
		return
	}

	if ret.Proto != Pem {
		return
	}

	path, err := path.Expand(ret.Value())
	if err != nil {
		err = errors.Wrapf(err, "Loading identity [%v]", str)
		return
	}

	key, err := crypto.ReadPrivateKeyFile(path, crypto.PKCS1Decoder)
	if err != nil {
		return
	}

	ret = ByKey(key.Public())
	return
}
