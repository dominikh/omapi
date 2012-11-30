package omapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
)

type Authenticator interface {
	Sign(*Message) []byte
	AuthObject() map[string][]byte
	AuthLen() int32
	AuthID() int32
	SetAuthID(int32)
}

type nullAuthenticator struct{}

func (_ *nullAuthenticator) AuthObject() map[string][]byte {
	return make(map[string][]byte)
}

func (_ *nullAuthenticator) Sign(_ *Message) []byte {
	return []byte("")
}

func (_ *nullAuthenticator) AuthLen() int32 {
	return 0
}

func (_ *nullAuthenticator) AuthID() int32 {
	return 0
}

func (_ *nullAuthenticator) SetAuthID(_ int32) {
}

type hmacMD5Authenticator struct {
	username string
	key      []byte
	authID   int32
}

func (auth *hmacMD5Authenticator) AuthObject() map[string][]byte {
	ret := make(map[string][]byte)
	ret["name"] = []byte(auth.username)
	ret["algorithm"] = []byte("hmac-md5.SIG-ALG.REG.INT.")

	return ret
}

func (auth *hmacMD5Authenticator) Sign(m *Message) []byte {
	hmac := hmac.New(md5.New, auth.key)

	// The signature's length is part of the message that we are
	// signing, so initialize the signature with the correct length.
	m.Signature = bytes.Repeat([]byte("\x00"), int(auth.AuthLen()))
	hmac.Write(m.Bytes(true))

	return hmac.Sum(nil)
}

func (_ *hmacMD5Authenticator) AuthLen() int32 {
	return 16
}

func (auth *hmacMD5Authenticator) AuthID() int32 {
	return auth.authID
}

func (auth *hmacMD5Authenticator) SetAuthID(val int32) {
	auth.authID = val
}
