package main // FIXME omapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"time"
)

type Opcode int32
type State int32

const (
	OpOpen Opcode = 1 + iota
	OpRefresh
	OpUpdate
	OpNotify
	OpStatus
	OpDelete
)

const (
	StateFree = 1 + iota
	StateActive
	StateExpired
	StateReleased
	StateAbandoned
	StateReset
	StateBackup
	StateReserved
	StateBootp
)

var Ethernet = []byte{0, 0, 0, 1}
var TokenRing = []byte{0, 0, 0, 6}
var FDDI = []byte{0, 0, 0, 8}

var True = []byte{0, 0, 0, 1}

func (opcode Opcode) String() (ret string) {
	switch opcode {
	case 1:
		ret = "open"
	case 2:
		ret = "refresh"
	case 3:
		ret = "update"
	case 4:
		ret = "notify"
	case 5:
		ret = "status"
	case 6:
		ret = "delete"
	}

	return
}

func (state State) String() (ret string) {
	switch state {
	case 1:
		ret = "free"
	case 2:
		ret = "active"
	case 3:
		ret = "expired"
	case 4:
		ret = "released"
	case 5:
		ret = "abandoned"
	case 6:
		ret = "reset"
	case 7:
		ret = "backup"
	case 8:
		ret = "reserved"
	case 9:
		ret = "bootp"
	}

	return
}

// TODO add size checks for all operations
type buffer struct {
	buffer *bytes.Buffer
}

func newBuffer() *buffer {
	return &buffer{new(bytes.Buffer)}
}

func (b *buffer) add_bytes(data []byte) {
	b.buffer.Write(data)
}

func (b *buffer) add(data interface{}) {
	err := binary.Write(b.buffer, binary.BigEndian, data)
	if err != nil {
		panic(err)
	}
}

func (b *buffer) add_map(data map[string][]byte) {
	// We need to add the map in a deterministic order for signing to
	// work, so we first sort the keys in alphabetical order, then use
	// that order to access the map entries.

	keys := make(sort.StringSlice, 0, len(data))

	for key := range data {
		keys = append(keys, key)
	}

	sort.Sort(keys)

	for _, key := range keys {
		value := data[key]

		b.add(int16(len(key)))
		b.add([]byte(key))

		b.add(int32(len(value)))
		b.add(value)
	}

	b.add([]byte("\x00\x00"))
}

func (b *buffer) bytes() []byte {
	return b.buffer.Bytes()
}

type Message struct {
	AuthID    int32
	Opcode    Opcode
	Handle    int32
	Tid       int32
	Rid       int32
	Message   map[string][]byte
	Object    map[string][]byte
	Signature []byte
}

func NewMessage() *Message {
	msg := &Message{
		Tid:     rand.Int31(),
		Message: make(map[string][]byte),
		Object:  make(map[string][]byte),
	}

	return msg
}

func NewOpenMessage(typeName string) *Message {
	message := NewMessage()
	message.Opcode = OpOpen
	message.Message["type"] = []byte(typeName)

	return message
}

func NewCreateMessage(typeName string) *Message {
	message := NewOpenMessage(typeName)
	message.Message["create"] = True
	// TODO Where is "exclusive" coming from? Is that always required
	// for creates, or only for hosts?
	message.Message["exclusive"] = True

	return message
}

func NewDeleteMessage(handle int32) *Message {
	message := NewMessage()
	message.Opcode = OpDelete
	message.Handle = handle

	return message
}

func (m *Message) Bytes(forSigning bool) []byte {
	ret := newBuffer()
	if !forSigning {
		ret.add(m.AuthID)
	}

	ret.add(int32(len(m.Signature)))
	ret.add(m.Opcode)
	ret.add(m.Handle)
	ret.add(m.Tid)
	ret.add(m.Rid)
	ret.add_map(m.Message)
	ret.add_map(m.Object)
	if !forSigning {
		ret.add(m.Signature)
	}

	return ret.buffer.Bytes()
}

func (m *Message) Sign(auth Authenticator) {
	m.AuthID = auth.AuthID()
	m.Signature = auth.Sign(m)
}

func (m *Message) Verify(auth Authenticator) bool {
	return bytes.Equal(auth.Sign(m), m.Signature)
}

func (m *Message) IsResponseTo(other *Message) bool {
	return m.Rid == other.Tid
}

type Connection struct {
	Hostname      string
	Port          int
	Username      string
	Key           string
	Authenticator Authenticator
	connection    *net.TCPConn
	inBuffer      *bytes.Buffer
}

func NewConnection(hostname string, port int, username string, key string) *Connection {
	con := &Connection{
		Hostname:      hostname,
		Port:          port,
		Username:      username,
		Key:           key,
		Authenticator: new(NullAuthenticator),
		inBuffer:      new(bytes.Buffer),
	}

	var newAuth Authenticator = new(NullAuthenticator)

	if len(username) > 0 && len(key) > 0 {
		decodedKey, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			panic(err)
		}
		newAuth = &HMACMD5Authenticator{username, decodedKey, -1}
	}

	raddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		// TODO return the error instead
		panic(err)
	}
	tcpConn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		// TODO return the error instead
		panic(err)
	}

	con.connection = tcpConn

	con.sendProtocolInitialization()
	con.receiveProtocolInitialization()
	con.initializeAuthenticator(newAuth)

	return con
}

func (con *Connection) initializeAuthenticator(auth Authenticator) {
	if _, ok := auth.(*NullAuthenticator); ok {
		return
	}

	message := NewOpenMessage("authenticator")
	for key, value := range auth.AuthObject() {
		message.Object[key] = value
	}

	response := con.Query(message)

	if response.Opcode != OpUpdate {
		panic("received non-update response for open")
	}

	if response.Handle == 0 {
		panic("received invalid authid from server")
	}

	auth.SetAuthID(response.Handle)
	con.Authenticator = auth
}

func (con *Connection) Query(msg *Message) *Message {
	msg.Sign(con.Authenticator)
	con.send(msg.Bytes(false))
	response := con.parseMessage()
	if !response.IsResponseTo(msg) {
		panic("received message is not the desired response")
	}

	// TODO check authid

	return response
}

func (con *Connection) send(data []byte) (n int, err error) {
	return con.connection.Write(data)
}

func (con *Connection) sendProtocolInitialization() {
	buf := newBuffer()
	buf.add(int32(100)) // Protocol version
	buf.add(int32(24))  // Header size
	con.send(buf.bytes())
}

func (con *Connection) read() {
	buf := make([]byte, 2048)
	n, err := con.connection.Read(buf)
	if err != nil {
		panic(err)
	}

	con.inBuffer.Write(buf[0:n])
}

func (con *Connection) waitForN(n int) {
	for con.inBuffer.Len() < n {
		con.read()
	}
}

func (con *Connection) parseStartupMessage() (version, headerSize int32) {
	con.waitForN(8)

	binary.Read(con.inBuffer, binary.BigEndian, &version)
	binary.Read(con.inBuffer, binary.BigEndian, &headerSize)

	return
}

func (con *Connection) parseMap() map[string][]byte {
	dict := make(map[string][]byte)

	var (
		keyLength   int16
		valueLength int32
		key         []byte
		value       []byte
	)

	for {
		con.waitForN(2)
		binary.Read(con.inBuffer, binary.BigEndian, &keyLength)
		if keyLength == 0 {
			// end of map
			break
		}

		con.waitForN(int(keyLength))
		key = make([]byte, keyLength)
		con.inBuffer.Read(key)

		con.waitForN(4)
		binary.Read(con.inBuffer, binary.BigEndian, &valueLength)
		con.waitForN(int(valueLength))
		value = make([]byte, valueLength)
		con.inBuffer.Read(value)

		dict[string(key)] = value
	}

	return dict
}

func (con *Connection) parseMessage() *Message {
	message := new(Message)
	con.waitForN(24) // authid + authlen + opcode + handle + tid + rid

	var authlen int32

	binary.Read(con.inBuffer, binary.BigEndian, &message.AuthID)
	binary.Read(con.inBuffer, binary.BigEndian, &authlen)
	binary.Read(con.inBuffer, binary.BigEndian, &message.Opcode)
	binary.Read(con.inBuffer, binary.BigEndian, &message.Handle)
	binary.Read(con.inBuffer, binary.BigEndian, &message.Tid)
	binary.Read(con.inBuffer, binary.BigEndian, &message.Rid)

	message.Message = con.parseMap()
	message.Object = con.parseMap()

	con.waitForN(int(authlen))
	message.Signature = make([]byte, authlen)
	con.inBuffer.Read(message.Signature)

	return message
}

func (con *Connection) receiveProtocolInitialization() {
	version, headerSize := con.parseStartupMessage()
	if version != 100 {
		panic("version mismatch")
	}

	if headerSize != 24 {
		panic("header size mismatch")
	}
}

type Authenticator interface {
	Sign(*Message) []byte
	AuthObject() map[string][]byte
	AuthLen() int32
	AuthID() int32
	SetAuthID(int32)
}

type NullAuthenticator struct{}

func (_ *NullAuthenticator) AuthObject() map[string][]byte {
	return make(map[string][]byte)
}

func (_ *NullAuthenticator) Sign(_ *Message) []byte {
	return []byte("")
}

func (_ *NullAuthenticator) AuthLen() int32 {
	return 0
}

func (_ *NullAuthenticator) AuthID() int32 {
	return 0
}

func (_ *NullAuthenticator) SetAuthID(_ int32) {
}

type HMACMD5Authenticator struct {
	Username string
	Key      []byte
	_AuthID  int32
}

func (auth *HMACMD5Authenticator) AuthObject() map[string][]byte {
	ret := make(map[string][]byte)
	ret["name"] = []byte(auth.Username)
	ret["algorithm"] = []byte("hmac-md5.SIG-ALG.REG.INT.")

	return ret
}

func (auth *HMACMD5Authenticator) Sign(m *Message) []byte {
	hmac := hmac.New(md5.New, auth.Key)

	// The signature's length is part of the message that we are
	// signing, so initialize the signature with the correct length.
	m.Signature = bytes.Repeat([]byte("\x00"), int(auth.AuthLen()))
	hmac.Write(m.Bytes(true))

	return hmac.Sum(nil)
}

func (_ *HMACMD5Authenticator) AuthLen() int32 {
	return 16
}

func (auth *HMACMD5Authenticator) AuthID() int32 {
	return auth._AuthID
}

func (auth *HMACMD5Authenticator) SetAuthID(val int32) {
	auth._AuthID = val
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	key := os.Getenv("OMAPI_KEY")
	connection := NewConnection("192.168.1.1", 7911, "omapi_key", key)

	// message := NewOpenMessage("lease")
	// mac, _ := net.ParseMAC("bc:ae:c5:76:1d:5a")
	// message.Object["hardware-address"] = []byte(mac)
	// response := connection.queryServer(message)
	// fmt.Println(response)

	// message := NewOpenMessage("host")
	// // message.Message["create"] = Ethernet
	// mac, _ := net.ParseMAC("08:00:27:4f:72:21")
	// message.Object["hardware-address"] = []byte(mac)

	// // buf := new(bytes.Buffer)
	// // binary.Write(buf, binary.BigEndian, int32(1))

	// message.Object["hardware-type"] = Ethernet

	// response := connection.queryServer(message)
	// fmt.Println(response)
	// response = connection.queryServer(NewDeleteMessage(response.Handle))
	// fmt.Println(response)

	mac, _ := net.ParseMAC("08:00:27:4f:72:21")
	ip := net.ParseIP("192.168.1.33")
	message := NewCreateMessage("host")

	message.Object["hardware-address"] = []byte(mac)
	message.Object["hardware-type"] = Ethernet
	message.Object["ip-address"] = []byte(ip[12:])
	message.Object["statements"] = []byte("ddns-hostname=\"win7.vm\";")
	message.Object["name"] = []byte("win7.vm")

	response := connection.queryServer(message)
	if response.Opcode != OpUpdate {
		fmt.Println("add failed:", string(response.Message["message"]))
	}
	// fmt.Println(response)
}
