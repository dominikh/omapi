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

type LeaseState int32

const (
	_              = iota
	LeaseStateFree = iota
	LeaseStateActive
	LeaseStateExpired
	LeaseStateReleased
	LeaseStateAbandoned
	LeaseStateReset
	LeaseStateBackup
	LeaseStateReserved
	LeaseStateBootp
)

func (state LeaseState) String() (ret string) {
	switch state {
	case LeaseStateFree:
		ret = "free"
	case LeaseStateActive:
		ret = "active"
	case LeaseStateExpired:
		ret = "expired"
	case LeaseStateReleased:
		ret = "released"
	case LeaseStateAbandoned:
		ret = "abandoned"
	case LeaseStateReset:
		ret = "reset"
	case LeaseStateBackup:
		ret = "backup"
	case LeaseStateReserved:
		ret = "reserved"
	case LeaseStateBootp:
		ret = "bootp"
	}

	return
}

func (state LeaseState) toBytes() []byte {
	return int32ToBytes(int32(state))
}

type FailoverState int32

const (
	FailoverStateStartup                   FailoverState = 1
	FailoverStateNormal                                  = 2
	FailoverStateCommunicationsInterrupted               = 3
	FailoverStatePartnerDown                             = 4
	FailoverStatePotentialConflict                       = 5
	FailoverStateRecover                                 = 6
	FailoverStatePaused                                  = 7
	FailoverStateShutdown                                = 8
	FailoverStateRecoverDone                             = 9
	FailoverStateResolutionInterrupted                   = 10
	FailoverStateConflictDone                            = 11
	FailoverStateRecoverWait                             = 254
)

func (state FailoverState) toBytes() []byte {
	return int32ToBytes(int32(state))
}

func (state FailoverState) String() (ret string) {
	switch state {
	case FailoverStateStartup:
		ret = "startup"
	case FailoverStateNormal:
		ret = "normal"
	case FailoverStateCommunicationsInterrupted:
		ret = "communications interrupted"
	case FailoverStatePartnerDown:
		ret = "partner down"
	case FailoverStatePotentialConflict:
		ret = "potential conflict"
	case FailoverStateRecover:
		ret = "recover"
	case FailoverStatePaused:
		ret = "paused"
	case FailoverStateShutdown:
		ret = "shutdown"
	case FailoverStateRecoverDone:
		ret = "recover done"
	case FailoverStateResolutionInterrupted:
		ret = "resolution interrupted"
	case FailoverStateConflictDone:
		ret = "conflict done"
	case FailoverStateRecoverWait:
		ret = "recover wait"
	}

	return
}

type FailoverHierarchy int32

const (
	HierarchyPrimary FailoverHierarchy = iota
	HierarchySecondary
)

func (h FailoverHierarchy) String() (ret string) {
	switch h {
	case HierarchyPrimary:
		ret = "primary"
	case HierarchySecondary:
		ret = "secondary"
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

var (
	True  = []byte{0, 0, 0, 1}
	False = []byte{0, 0, 0, 0}
)

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
		if len(value) > 0 {
			b.add(value)
		}
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
		State:                LeaseState(state),
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

func (m *Message) toFailover() Failover {
	partnerPort := bytesToInt32(m.Object["partner-port"])
	localPort := bytesToInt32(m.Object["local-port"])
	maxOutstandingUpdates := bytesToInt32(m.Object["max-outstanding-updates"])
	mclt := bytesToInt32(m.Object["mclt"])
	loadBalanceMaxSecs := bytesToInt32(m.Object["load-balance-max-secs"])
	localState := bytesToInt32(m.Object["local-state"])
	partnerState := bytesToInt32(m.Object["partner-state"])
	localStos := bytesToInt32(m.Object["local-stos"])
	partnerStos := bytesToInt32(m.Object["partner-stos"])
	hierarchy := bytesToInt32(m.Object["hierarchy"])
	lastPacketSent := bytesToInt32(m.Object["last-packet-sent"])
	lastTimestampReceived := bytesToInt32(m.Object["last-timestamp-received"])
	skew := bytesToInt32(m.Object["skew"])
	maxResponseDelay := bytesToInt32(m.Object["max-response-delay"])
	curUnackedUpdates := bytesToInt32(m.Object["cur-unacked-updates"])

	return Failover{
		Name:                  string(m.Object["name"]),
		PartnerAddress:        net.IP(m.Object["partner-address"]),
		LocalAddress:          net.IP(m.Object["local-address"]),
		PartnerPort:           partnerPort,
		LocalPort:             localPort,
		MaxOutstandingUpdates: maxOutstandingUpdates,
		Mclt:                  mclt,
		LoadBalanceMaxSecs:    loadBalanceMaxSecs,
		LoadBalanceHBA:        m.Object["load-balance-hba"],
		LocalState:            FailoverState(localState),
		PartnerState:          FailoverState(partnerState),
		LocalStos:             time.Unix(int64(localStos), 0),
		PartnerStos:           time.Unix(int64(partnerStos), 0),
		Hierarchy:             FailoverHierarchy(hierarchy),
		LastPacketSent:        time.Unix(int64(lastPacketSent), 0),
		LastTimestampReceived: time.Unix(int64(lastTimestampReceived), 0),
		Skew:                  skew,
		MaxResponseDelay:      maxResponseDelay,
		CurUnackedUpdates:     curUnackedUpdates,
	}
}

type Host struct {
	Name                 string
	Group                int32 // TODO
	HardwareAddress      net.HardwareAddr
	HardwareType         HardwareType
	DHCPClientIdentifier []byte
	IP                   net.IP
	Statements           string // Not populated by OMAPI
	Known                bool   // Not populated by OMAPI
	Handle               int32
}

func (host Host) toObject() map[string][]byte {
	object := make(map[string][]byte)

	object["name"] = []byte(host.Name)

	if len([]byte(host.IP)) > 0 {
		object["ip-address"] = []byte(host.IP)[12:]
	} else {
		object["ip-address"] = nil
	}

	object["hardware-address"] = []byte(host.HardwareAddress)
	if host.HardwareType == 0 {
		object["hardware-type"] = nil
	} else {
		object["hardware-type"] = host.HardwareType.toBytes()
	}

	// TODO remove statements field when updating an object, to work around bug
	object["statements"] = []byte(host.Statements)

	object["dhcp-client-identifier"] = host.DHCPClientIdentifier

	return object
}

type Lease struct {
	State                LeaseState
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

func (lease Lease) toObject() map[string][]byte {
	object := make(map[string][]byte)

	// TODO check if sending the state in an update will cause an
	// error
	if lease.State > 0 {
		object["state"] = lease.State.toBytes()
	} else {
		object["state"] = nil
	}

	// TODO check if sending the IP in an update will cause an
	// error
	if len([]byte(lease.IP)) > 0 {
		object["ip-address"] = []byte(lease.IP)[12:]
	} else {
		object["ip-address"] = nil
	}

	object["dhcp-client-identifier"] = lease.DHCPClientIdentifier
	object["client-hostname"] = []byte(lease.ClientHostname)
	object["hardware-address"] = []byte(lease.HardwareAddress)

	if lease.HardwareType == 0 {
		object["hardware-type"] = nil
	} else {
		object["hardware-type"] = lease.HardwareType.toBytes()
	}

	return object
}

type Failover struct {
	Name                  string
	PartnerAddress        net.IP
	LocalAddress          net.IP
	PartnerPort           int32
	LocalPort             int32
	MaxOutstandingUpdates int32
	Mclt                  int32 // TODO maybe find a better name
	LoadBalanceMaxSecs    int32
	LoadBalanceHBA        []byte // TODO what type would this be?
	LocalState            FailoverState
	PartnerState          FailoverState
	LocalStos             time.Time // TODO maybe find a better name
	PartnerStos           time.Time // TODO maybe find a better name
	Hierarchy             FailoverHierarchy
	LastPacketSent        time.Time
	LastTimestampReceived time.Time
	Skew                  int32
	MaxResponseDelay      int32
	CurUnackedUpdates     int32
}

type Connection struct {
	authenticator Authenticator
	connection    net.Conn
	inBuffer      *bytes.Buffer
}

// Dial establishes a connection to an OMAPI-enabled server.
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

// Query sends a message to the server and waits for a reply. It
// returns the underlying response as well as its representation as a
// status. If the message didn't contain a status, the success status
// will be returned instead.
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

func (con *Connection) FindHost(host Host) (Host, error) {
	message := NewOpenMessage("host")

	message.Object = host.toObject()

	response, status := con.Query(message)
	if response.Opcode == OpUpdate {
		return response.toHost(), nil
	}

	return Host{}, status
}

func (con *Connection) FindLease(lease Lease) (Lease, error) {
	// - IP works
	// - DHCPClientIdentifier works
	// - State does not, even though documentation claims it does
	// - ClientHostname does not, even though documentation claims it does
	message := NewOpenMessage("lease")

	message.Object = lease.toObject()

	response, status := con.Query(message)
	if response.Opcode == OpUpdate {
		return response.toLease(), nil
	}

	return Lease{}, status
}

func (con *Connection) FindFailover(name string) (Failover, error) {
	message := NewOpenMessage("failover-state")

	message.Object["name"] = []byte(name)

	response, status := con.Query(message)
	if response.Opcode == OpUpdate {
		return response.toFailover(), nil
	}

	return Failover{}, status
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

// CreateHost creates a new host object on the server. The passed
// argument with its fields populated will be sent to the server and
// saved, if possible. The server's representation of the new host
// will be returned.
//
// The returned object will be incomplete compared to the original
// argument, because OMAPI doesn't transfer all information back to
// us.
//
// Example:
//	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
//	host := Host{
//		Name:            "new_host",
//		HardwareAddress: mac,
//		HardwareType:    Ethernet,
//		IP:              net.ParseIP("10.0.0.2"),
//		Statements:      `ddns-hostname "the.hostname";`,
//	}
//
//	newHost, err := connection.CreateHost(host)
//	if err != nil {
//		// Couldn't create the new host, error string will tell us why
//	} else {
//		// We successfuly created a new host. newHost will contain the
//		// OMAPI representation of it, including a handle
//	}
func (con *Connection) CreateHost(host Host) (Host, error) {
	message := NewCreateMessage("host")
	message.Object = host.toObject()

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
