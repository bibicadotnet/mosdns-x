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

	r           *dns.Msg
	responseGen uint64 // Tăng tiến mỗi khi có response mới (từ cache hoặc upstream)
	cachedGen   uint64 // Lưu version của response đã được ghi vào cache thành công
	marks       map[uint]struct{}
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
func (ctx *Context) R() *dns.Msg {
	return ctx.r
}

// SetResponse stores the response r to the context and increments generation.
func (ctx *Context) SetResponse(r *dns.Msg) {
	ctx.r = r
	ctx.responseGen++ // Đánh dấu một "thế hệ" response mới
}

// ResponseGen returns the current response generation.
func (ctx *Context) ResponseGen() uint64 {
	return ctx.responseGen
}

// MarkAsCached records that the current response generation has been cached.
func (ctx *Context) MarkAsCached() {
	ctx.cachedGen = ctx.responseGen
}

// IsAlreadyCached reports whether the current response generation is already cached.
func (ctx *Context) IsAlreadyCached() bool {
	return ctx.r != nil && ctx.cachedGen == ctx.responseGen
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
// ShallowCopyForBackground creates a lightweight copy of this Context for lazy updates.
func (ctx *Context) ShallowCopyForBackground() *Context {
	return &Context{
		startTime:     ctx.startTime,
		q:             ctx.q.Copy(),
		originalQuery: ctx.originalQuery,
		reqMeta:       ctx.reqMeta,
		id:            ctx.id,
		// responseGen và cachedGen mặc định về 0.
		// Luồng lazy sẽ tự quản lý versioning của riêng nó.
	}
}

// CopyTo deep copies this Context to d.
func (ctx *Context) CopyTo(d *Context) *Context {
	d.startTime = ctx.startTime
	d.q = ctx.q.Copy()
	d.originalQuery = ctx.originalQuery
	d.reqMeta = ctx.reqMeta
	d.id = ctx.id
	d.responseGen = ctx.responseGen
	d.cachedGen = ctx.cachedGen

	if r := ctx.r; r != nil {
		d.r = r.Copy()
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
