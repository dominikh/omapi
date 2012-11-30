// Package omapi implements the OMAPI protocol of the ISC DHCP server,
// allowing it to query and modify objects as well as control the
// server itself.
package omapi

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sort"
	"time"
)

type Opcode int32

const (
	_             = iota
	OpOpen Opcode = iota
	OpRefresh
	OpUpdate
	OpNotify
	OpStatus
	OpDelete
)

func (opcode Opcode) String() (ret string) {
	switch opcode {
	case OpOpen:
		ret = "open"
	case OpRefresh:
		ret = "refresh"
	case OpUpdate:
		ret = "update"
	case OpNotify:
		ret = "notify"
	case OpStatus:
		ret = "status"
	case OpDelete:
		ret = "delete"
	}

	return
}

type State int32

const (
	_         = iota
	StateFree = iota
	StateActive
	StateExpired
	StateReleased
	StateAbandoned
	StateReset
	StateBackup
	StateReserved
	StateBootp
)

func (state State) String() (ret string) {
	switch state {
	case StateFree:
		ret = "free"
	case StateActive:
		ret = "active"
	case StateExpired:
		ret = "expired"
	case StateReleased:
		ret = "released"
	case StateAbandoned:
		ret = "abandoned"
	case StateReset:
		ret = "reset"
	case StateBackup:
		ret = "backup"
	case StateReserved:
		ret = "reserved"
	case StateBootp:
		ret = "bootp"
	}

	return
}

type Status struct {
	Code    int32
	Message string
}

// IsError returns true if the status is describing an error.
func (s Status) IsError() bool {
	return s.Code > 0
}

func (s Status) Error() string {
	return s.Message
}

type HardwareType int32

const (
	Ethernet  HardwareType = 1
	TokenRing              = 6
	FDDI                   = 8
)

func (hw HardwareType) toBytes() []byte {
	return int32ToBytes(int32(hw))
}

func (hw HardwareType) String() (ret string) {
	switch hw {
	case Ethernet:
		ret = "Ethernet"
	case TokenRing:
		ret = "Token ring"
	case FDDI:
		ret = "FDDI"
	}

	return
}

const DefaultPort = 7911

var True = []byte{0, 0, 0, 1}
var False = []byte{0, 0, 0, 0}

// TODO add size checks for all operations
type buffer struct {
	buffer *bytes.Buffer
}

func newBuffer() *buffer {
	return &buffer{new(bytes.Buffer)}
}

func (b *buffer) addBytes(data []byte) {
	b.buffer.Write(data)
}

func (b *buffer) add(data interface{}) {
	if err := binary.Write(b.buffer, binary.BigEndian, data); err != nil {
		panic(err)
	}
}

func (b *buffer) addMap(data map[string][]byte) {
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

func int32ToBytes(i int32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(i))

	return b
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
	ret.addMap(m.Message)
	ret.addMap(m.Object)
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
		HardwareType:         HardwareType(bytesToInt32(m.Object["hardware-type"])),
		DHCPClientIdentifier: m.Object["dhcp-client-identifier"],
		IP:                   net.IP(m.Object["ip-address"]),
		Handle:               m.Handle,
	}
}

func (m *Message) toStatus() Status {
	if m.Opcode != OpStatus {
		return Statuses[0]
	}

	return Statuses[bytesToInt32(m.Message["result"])]
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
		HardwareType:         HardwareType(bytesToInt32(m.Object["hardware-type"])),
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
	HardwareType         HardwareType
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
	HardwareType    HardwareType
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
		authenticator: new(nullAuthenticator),
		inBuffer:      new(bytes.Buffer),
	}

	var newAuth Authenticator = new(nullAuthenticator)

	if len(username) > 0 && len(key) > 0 {
		decodedKey, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			panic(err)
		}
		newAuth = &hmacMD5Authenticator{username, decodedKey, -1}
	}

	tcpConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	con.connection = tcpConn

	con.sendProtocolInitialization()
	if err := con.receiveProtocolInitialization(); err != nil {
		return nil, err
	}

	if err := con.initializeAuthenticator(newAuth); err != nil {
		return nil, err
	}

	return con, nil
}

func (con *Connection) initializeAuthenticator(auth Authenticator) error {
	if _, ok := auth.(*nullAuthenticator); ok {
		return nil
	}

	message := NewOpenMessage("authenticator")
	for key, value := range auth.AuthObject() {
		message.Object[key] = value
	}

	response, _ := con.Query(message)

	if response.Opcode != OpUpdate {
		return errors.New("received non-update response for open")
	}

	if response.Handle == 0 {
		return errors.New("received invalid authid from server")
	}

	auth.SetAuthID(response.Handle)
	con.authenticator = auth

	return nil
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

func (con *Connection) receiveProtocolInitialization() error {
	version, headerSize := con.parseStartupMessage()
	if version != 100 {
		return errors.New("version mismatch")
	}

	if headerSize != 24 {
		return errors.New("header size mismatch")
	}

	return nil
}

func (con *Connection) FindHostByName(name string) (Host, error) {
	message := NewOpenMessage("host")
	message.Object["name"] = []byte(name)

	response, status := con.Query(message)
	if response.Opcode == OpUpdate {
		return response.toHost(), nil
	}

	return Host{}, status
}

func (con *Connection) Delete(handle int32) error {
	message := NewMessage()
	message.Opcode = OpDelete
	message.Handle = handle

	_, status := con.Query(message)

	if status.IsError() {
		return status
	}

	return nil
}

func (con *Connection) CreateHost(host Host) (Host, error) {
	message := NewCreateMessage("host")
	message.Object["name"] = []byte(host.Name)
	message.Object["hardware-address"] = []byte(host.HardwareAddress)
	message.Object["hardware-type"] = host.HardwareType.toBytes()
	message.Object["ip-address"] = []byte(host.IP)[12:]

	if len(host.Statements) > 0 {
		message.Object["statements"] = []byte(host.Statements)
	}

	if len(host.DHCPClientIdentifier) > 0 {
		message.Object["dhcp-client-identifier"] = host.DHCPClientIdentifier
	}

	// The server doesn't currently care about Known

	// if host.Known {
	//	message.Object["known"] = True
	// } else {
	//	message.Object["known"] = False
	// }

	response, status := con.Query(message)

	if status.IsError() {
		return Host{}, status
	}

	return response.toHost(), nil
}
