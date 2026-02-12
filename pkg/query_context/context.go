package query_context

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

const (
	ProtocolUDP   = "udp"
	ProtocolTCP   = "tcp"
	ProtocolTLS   = "tls"
	ProtocolQUIC  = "quic"
	ProtocolHTTP  = "http"
	ProtocolHTTPS = "https"
	ProtocolH2    = "h2"
	ProtocolH3    = "h3"
)

type RequestMeta struct {
	clientAddr netip.Addr
	serverName string
	protocol   string
}

func NewRequestMeta(addr netip.Addr) *RequestMeta {
	meta := new(RequestMeta)
	meta.SetClientAddr(addr)
	return meta
}

func (m *RequestMeta) SetClientAddr(addr netip.Addr) {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	m.clientAddr = addr
}

func (m *RequestMeta) SetProtocol(protocol string) {
	m.protocol = protocol
}

func (m *RequestMeta) SetServerName(serverName string) {
	m.serverName = serverName
}

func (m *RequestMeta) GetClientAddr() netip.Addr {
	return m.clientAddr
}

func (m *RequestMeta) GetProtocol() string {
	return m.protocol
}

func (m *RequestMeta) GetServerName() string {
	return m.serverName
}

type Context struct {
	startTime     time.Time
	q             *dns.Msg
	originalQuery *dns.Msg
	id            uint32
	reqMeta       *RequestMeta

	r     *dns.Msg
	marks map[uint]struct{}

	// Transport optimization fields
	rawR            []byte
	rawRReleaseFunc func()
}

var (
	contextUid      uint32
	zeroRequestMeta = &RequestMeta{}
)

func NewContext(q *dns.Msg, meta *RequestMeta) *Context {
	if q == nil {
		panic("handler: query msg is nil")
	}

	if meta == nil {
		meta = zeroRequestMeta
	}

	ctx := &Context{
		q:             q,
		originalQuery: q.Copy(),
		reqMeta:       meta,
		id:            atomic.AddUint32(&contextUid, 1),
		startTime:     time.Now(),
	}

	return ctx
}

func (ctx *Context) String() string {
	var question string
	if len(ctx.q.Question) >= 1 {
		q := ctx.q.Question[0]
		question = fmt.Sprintf("%s %s %s", q.Name, dnsutils.QclassToString(q.Qclass), dnsutils.QtypeToString(q.Qtype))
	} else {
		question = "empty question"
	}
	return fmt.Sprintf("%s %d %d", question, ctx.q.Id, ctx.id)
}

func (ctx *Context) Q() *dns.Msg {
	return ctx.q
}

func (ctx *Context) OriginalQuery() *dns.Msg {
	return ctx.originalQuery
}

func (ctx *Context) ReqMeta() *RequestMeta {
	return ctx.reqMeta
}

func (ctx *Context) R() *dns.Msg {
	return ctx.r
}

// SetResponse stores the response and clears rawR to maintain consistency.
func (ctx *Context) SetResponse(r *dns.Msg) {
	ctx.r = r
	// Clear raw response to avoid inconsistent state
	ctx.rawR = nil
	ctx.rawRReleaseFunc = nil
}

// SetRawResponse sets the pre-patched wire format response and clears the logical response r.
func (ctx *Context) SetRawResponse(raw []byte, releaseFunc func()) {
	ctx.r = nil // Clear logical response to maintain consistency
	ctx.rawR = raw
	ctx.rawRReleaseFunc = releaseFunc
}

// RawR returns the raw response bytes.
func (ctx *Context) RawR() []byte {
	return ctx.rawR
}

// ReleaseRawR releases the raw response buffer.
func (ctx *Context) ReleaseRawR() {
	if ctx.rawRReleaseFunc != nil {
		ctx.rawRReleaseFunc()
		ctx.rawR = nil
		ctx.rawRReleaseFunc = nil
	}
}

func (ctx *Context) Id() uint32 {
	return ctx.id
}

func (ctx *Context) StartTime() time.Time {
	return ctx.startTime
}

func (ctx *Context) InfoField() zap.Field {
	return zap.Stringer("query", ctx)
}

func (ctx *Context) Copy() *Context {
	newCtx := new(Context)
	ctx.CopyTo(newCtx)
	return newCtx
}

// CopyTo deep copies the logical state. 
// rawR is NOT copied as it belongs to the transport layer and pooled buffers.
func (ctx *Context) CopyTo(d *Context) *Context {
	d.startTime = ctx.startTime
	d.q = ctx.q.Copy()
	d.originalQuery = ctx.originalQuery
	d.reqMeta = ctx.reqMeta
	d.id = ctx.id

	if r := ctx.r; r != nil {
		d.r = r.Copy()
	}

	for m := range ctx.marks {
		d.AddMark(m)
	}
	return d
}

func (ctx *Context) AddMark(m uint) {
	if ctx.marks == nil {
		ctx.marks = make(map[uint]struct{})
	}
	ctx.marks[m] = struct{}{}
}

func (ctx *Context) HasMark(m uint) bool {
	_, ok := ctx.marks[m]
	return ok
}

var allocatedMark struct {
	sync.Mutex
	u uint
}

var errMarkOverflowed = errors.New("too many allocated marks")

func AllocateMark() (uint, error) {
	allocatedMark.Lock()
	defer allocatedMark.Unlock()
	m := allocatedMark.u + 1
	if m == 0 {
		return 0, errMarkOverflowed
	}
	allocatedMark.u++
	return m, nil
}
