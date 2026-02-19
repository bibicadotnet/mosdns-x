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

// RequestMeta represents some metadata about the request.
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

// Context is a query context that pass through plugins
type Context struct {
	startTime     time.Time
	q             *dns.Msg
	originalQuery *dns.Msg // lazy init
	id            uint32
	reqMeta       *RequestMeta

	r     *dns.Msg
	rawR  []byte // wire format response (e.g., from cache)
	marks map[uint]struct{}
}

var (
	contextUid      uint32
	zeroRequestMeta = &RequestMeta{}
)

// NewContext creates a new query Context.
func NewContext(q *dns.Msg, meta *RequestMeta) *Context {
	if q == nil {
		panic("handler: query msg is nil")
	}

	if meta == nil {
		meta = zeroRequestMeta
	}

	return &Context{
		q:         q,
		reqMeta:   meta,
		id:        atomic.AddUint32(&contextUid, 1),
		startTime: time.Now(),
		// originalQuery is nil by default, lazy init in OriginalQuery()
	}
}

// String returns a short summary of its query.
// Optimized: Trust the gatekeeper (_misc_optm). len(q.Question) is guaranteed to be 1.
func (ctx *Context) String() string {
	q := ctx.q.Question[0]
	return fmt.Sprintf("%s %s %s %d %d",
		q.Name,
		dnsutils.QclassToString(q.Qclass),
		dnsutils.QtypeToString(q.Qtype),
		ctx.q.Id,
		ctx.id,
	)
}

// Q returns the query msg. It always returns a non-nil msg.
func (ctx *Context) Q() *dns.Msg {
	return ctx.q
}

// OriginalQuery returns the copied original query msg.
// Optimized: q.Copy() only happens when this is called (Lazy Init).
func (ctx *Context) OriginalQuery() *dns.Msg {
	if ctx.originalQuery == nil {
		ctx.originalQuery = ctx.q.Copy()
	}
	return ctx.originalQuery
}

// ReqMeta returns the request metadata.
func (ctx *Context) ReqMeta() *RequestMeta {
	return ctx.reqMeta
}

// R returns the response.
// If ctx.r is nil but ctx.rawR is not, it performs an on-demand Unpack and clears rawR.
func (ctx *Context) R() *dns.Msg {
	if ctx.r != nil {
		return ctx.r
	}
	if len(ctx.rawR) > 0 {
		m := new(dns.Msg)
		if err := m.Unpack(ctx.rawR); err == nil {
			ctx.r = m
			ctx.rawR = nil // Clear rawR to ensure consistency if r is modified.
			return m
		}
	}
	return nil
}

// SetResponse stores the response r to the context and clears rawR if r is not nil.
func (ctx *Context) SetResponse(r *dns.Msg) {
	if r == nil {
		return
	}
	ctx.r = r
	ctx.rawR = nil
}

// RawR returns the raw response.
func (ctx *Context) RawR() []byte {
	return ctx.rawR
}

// SetRawResponse stores the raw response b to the context and clears r if b is not nil.
func (ctx *Context) SetRawResponse(b []byte) {
	if b == nil {
		return
	}
	ctx.rawR = b
	ctx.r = nil
}

// Id returns the Context id.
func (ctx *Context) Id() uint32 {
	return ctx.id
}

// StartTime returns the time when the Context was created.
func (ctx *Context) StartTime() time.Time {
	return ctx.startTime
}

// InfoField returns a zap.Field.
func (ctx *Context) InfoField() zap.Field {
	return zap.Stringer("query", ctx)
}

// Copy deep copies this Context.
func (ctx *Context) Copy() *Context {
	newCtx := new(Context)
	ctx.CopyTo(newCtx)
	return newCtx
}

// ShallowCopyForBackground creates a lightweight copy of this Context.
func (ctx *Context) ShallowCopyForBackground() *Context {
	return &Context{
		startTime:     ctx.startTime,
		q:             ctx.q.Copy(),
		originalQuery: ctx.originalQuery,
		reqMeta:       ctx.reqMeta,
		id:            ctx.id,
	}
}

// CopyTo deep copies this Context to d.
func (ctx *Context) CopyTo(d *Context) *Context {
	d.startTime = ctx.startTime
	d.q = ctx.q.Copy()
	d.originalQuery = ctx.originalQuery
	d.reqMeta = ctx.reqMeta
	d.id = ctx.id

	if r := ctx.r; r != nil {
		d.r = r.Copy()
	}
	if ctx.rawR != nil {
		d.rawR = make([]byte, len(ctx.rawR))
		copy(d.rawR, ctx.rawR)
	}
	for m := range ctx.marks {
		d.AddMark(m)
	}
	return d
}

// AddMark adds mark m to this Context.
func (ctx *Context) AddMark(m uint) {
	if ctx.marks == nil {
		ctx.marks = make(map[uint]struct{})
	}
	ctx.marks[m] = struct{}{}
}

// HasMark reports whether this Context has mark m.
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
