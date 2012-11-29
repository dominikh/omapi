package omapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sort"
	"time"
)

type Opcode int32
type State int32

type Status struct {
	Code    int32
	Message string
}

var Statusses = []Status{
	Status{0, "success"},
	Status{1, "out of memory"},
	Status{2, "timed out"},
	Status{3, "no available threads"},
	Status{4, "address not available"},
	Status{5, "address in use"},
	Status{6, "permission denied"},
	Status{7, "no pending connections"},
	Status{8, "network unreachable"},
	Status{9, "host unreachable"},
	Status{10, "network down"},
	Status{11, "host down"},
	Status{12, "connection refused"},
	Status{13, "not enough free resources"},
	Status{14, "end of file"},
	Status{15, "socket already bound"},
	Status{16, "task is done"},
	Status{17, "lock busy"},
	Status{18, "already exists"},
	Status{19, "ran out of space"},
	Status{20, "operation canceled"},
	Status{21, "sending events is not allowed"},
	Status{22, "shutting down"},
	Status{23, "not found"},
	Status{24, "unexpected end of input"},
	Status{25, "failure"},
	Status{26, "I/O error"},
	Status{27, "not implemented"},
	Status{28, "unbalanced parentheses"},
	Status{29, "no more"},
	Status{30, "invalid file"},
	Status{31, "bad base64 encoding"},
	Status{32, "unexpected token"},
	Status{33, "quota reached"},
	Status{34, "unexpected error"},
	Status{35, "already running"},
	Status{36, "host unknown"},
	Status{37, "protocol version mismatch"},
	Status{38, "protocol error"},
	Status{39, "invalid argument"},
	Status{40, "not connected"},
	Status{41, "data not yet available"},
	Status{42, "object unchanged"},
	Status{43, "more than one object matches key"},
	Status{44, "key conflict"},
	Status{45, "parse error(s) occurred"},
	Status{46, "no key specified"},
	Status{47, "zone TSIG key not known"},
	Status{48, "invalid TSIG key"},
	Status{49, "operation in progress"},
	Status{50, "DNS format error"},
	Status{51, "DNS server failed"},
	Status{52, "no such domain"},
	Status{53, "not implemented"},
	Status{54, "refused"},
	Status{55, "domain already exists"},
	Status{56, "RRset already exists"},
	Status{57, "no such RRset"},
	Status{58, "not authorized"},
	Status{59, "not a zone"},
	Status{60, "bad DNS signature"},
	Status{61, "bad DNS key"},
	Status{62, "clock skew too great"},
	Status{63, "no root zone"},
	Status{64, "destination address required"},
	Status{65, "cross-zone update"},
	Status{66, "no TSIG signature"},
	Status{67, "not equal"},
	Status{68, "connection reset by peer"},
	Status{69, "unknown attribute"},
}

func (s Status) IsError() bool {
	return s.Code > 0
}

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

const DefaultPort = 7911

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
	message.Message["exclusive"] = True

	return message
}

func NewDeleteMessage(handle int32) *Message {
	message := NewMessage()
	message.Opcode = OpDelete
	message.Handle = handle

	return message
}

func bytesToInt32(b []byte) int32 {
	if len(b) < 4 {
		return 0
	}

	return int32(binary.BigEndian.Uint32(b))
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

func (m *Message) toHost() Host {
	return Host{
		Name:                 string(m.Object["name"]),
		HardwareAddress:      net.HardwareAddr(m.Object["hardware-address"]),
		HardwareType:         m.Object["hardware-type"],
		DHCPClientIdentifier: m.Object["dhcp-client-identifier"],
		IP:                   net.IP(m.Object["ip-address"]),
		Handle:               m.Handle,
	}
}

func (m *Message) toStatus() Status {
	if m.Opcode != OpStatus {
		return Statusses[0]
	}

	return Statusses[bytesToInt32(m.Message["result"])]
}

func (m *Message) toLease() Lease {
	state := bytesToInt32(m.Object["state"])
	host := bytesToInt32(m.Object["host"])
	ends := bytesToInt32(m.Object["ends"])
	tstp := bytesToInt32(m.Object["tstp"])
	atsfp := bytesToInt32(m.Object["atsfp"])
	cltt := bytesToInt32(m.Object["cltt"])

	return Lease{
		State:                State(state),
		IP:                   net.IP(m.Object["ip-address"]),
		DHCPClientIdentifier: m.Object["dhcp-client-identifier"],
		ClientHostname:       string(m.Object["client-hostname"]),
		Host:                 host,
		HardwareAddress:      net.HardwareAddr(m.Object["hardware-address"]),
		HardwareType:         m.Object["hardware-type"],
		Ends:                 time.Unix(int64(ends), 0),
		Tstp:                 time.Unix(int64(tstp), 0),
		Atsfp:                time.Unix(int64(atsfp), 0),
		Cltt:                 time.Unix(int64(cltt), 0),
		Handle:               m.Handle,
	}
}

type Host struct {
	Name                 string
	Group                int32 // TODO
	HardwareAddress      net.HardwareAddr
	HardwareType         []byte // TODO
	DHCPClientIdentifier []byte
	IP                   net.IP
	Statements           string
	Known                bool
	Handle               int32
}

type Lease struct {
	State                State
	IP                   net.IP
	DHCPClientIdentifier []byte
	ClientHostname       string
	Host                 int32 // TODO figure out what to do with handles
	// Subnet, Pool, BillingClass are "currently not supported" by the dhcpd
	HardwareAddress net.HardwareAddr
	HardwareType    []byte // TODO
	Ends            time.Time
	// TODO maybe find nicer names for these times
	Tstp   time.Time
	Atsfp  time.Time
	Cltt   time.Time
	Handle int32
}

type Connection struct {
	authenticator Authenticator
	connection    net.Conn
	inBuffer      *bytes.Buffer
}

func Dial(addr, username, key string) (*Connection, error) {
	con := &Connection{
		authenticator: new(NullAuthenticator),
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

	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	con.connection = tcpConn

	con.sendProtocolInitialization()
	con.receiveProtocolInitialization()
	con.initializeAuthenticator(newAuth)

	return con, nil
}

func (con *Connection) initializeAuthenticator(auth Authenticator) {
	if _, ok := auth.(*NullAuthenticator); ok {
		return
	}

	message := NewOpenMessage("authenticator")
	for key, value := range auth.AuthObject() {
		message.Object[key] = value
	}

	response, _ := con.Query(message)

	if response.Opcode != OpUpdate {
		panic("received non-update response for open")
	}

	if response.Handle == 0 {
		panic("received invalid authid from server")
	}

	auth.SetAuthID(response.Handle)
	con.authenticator = auth
}

func (con *Connection) Query(msg *Message) (*Message, Status) {
	msg.Sign(con.authenticator)
	con.send(msg.Bytes(false))
	response := con.parseMessage()
	if !response.IsResponseTo(msg) {
		panic("received message is not the desired response")
	}

	// TODO check authid

	return response, response.toStatus()
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
	con.waitForN(8) // version, headerSize

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
		con.waitForN(2) // key length
		binary.Read(con.inBuffer, binary.BigEndian, &keyLength)
		if keyLength == 0 {
			// end of map
			break
		}

		con.waitForN(int(keyLength)) // key
		key = make([]byte, keyLength)
		con.inBuffer.Read(key)

		con.waitForN(4) // value length
		binary.Read(con.inBuffer, binary.BigEndian, &valueLength)
		con.waitForN(int(valueLength)) // value
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

	con.waitForN(int(authlen)) // signature
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

func (con *Connection) FindHostByName(name string) (Host, error) {
	message := NewOpenMessage("host")
	message.Object["name"] = []byte(name)

	response, status := con.Query(message)
	if response.Opcode == OpUpdate {
		return response.toHost(), nil
	}

	return Host{}, errors.New(status.Message)
}

