// Package bodylimit is the v0.5 contract of the request body limits (D41, D44,
// D45, D46, contracts/body-limits.md): which connection, request and request body
// the gateway admits, how large a body of each class may be, what a body counts
// against the byte limit, how the receive rate is measured and how the limits are
// exposed to Prometheus.
//
// The limits protect the ingress, not a website, so they act in every mode,
// observe included. They are resource limits, not rate limits (D29), and
// nothing here exempts a body from inspection: a class only selects a limit.
package bodylimit

import (
	"encoding/json"
	"strings"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/jsonx"
	"github.com/deutschland-schild/schild/contract/schema"
)

// Defaults of schild.yaml waf.body and waf.raw_body_limit_bytes.
const (
	DefaultMaxPerClient     = 8
	DefaultMaxPerNetwork    = 32
	DefaultMaxInFlightBytes = int64(4) << 30
	DefaultRawLimitBytes    = int64(128) << 10
	// D44: memory of checked bodies waiting for the backend, per client and per
	// network, with the factor of net classes cgnat and mobile.
	DefaultMaxWaitingBytesPerClient  = int64(64) << 20
	DefaultMaxWaitingBytesPerNetwork = int64(256) << 20
	// D45: requests waiting for the backend, with or without a body, per client
	// and per network, with the factor of net classes cgnat and mobile.
	DefaultMaxWaitingPerClient  = 1024
	DefaultMaxWaitingPerNetwork = 4096
	// D46: open connections, per client and per network, with the same factor.
	// Twice the requests: on HTTP/1.1 each running request holds a connection,
	// and browsers keep others open and idle next to it.
	DefaultMaxConnsPerClient  = 2048
	DefaultMaxConnsPerNetwork = 8192
)

// SharedFactor multiplies the client and network limits for addresses many
// people share (net classes cgnat and mobile, like the evaluation slots).
const SharedFactor = 4

// max_in_flight when schild.yaml does not set it: InFlightPerGiB per GiB of
// memory, between MinInFlight and MaxInFlight; FallbackInFlight when the
// memory is unknown.
const (
	InFlightPerGiB   = 512
	MinInFlight      = 64
	MaxInFlight      = 65536
	FallbackInFlight = 1024
	gib              = int64(1) << 30
)

// MultipartWeight: a multipart body counts this many times against
// max_in_flight_bytes, because it lies on disk twice while Coraza copies its
// file parts.
const MultipartWeight = 2

// max_large_in_flight when schild.yaml does not set it: a large body, one over
// WaitingMemoryBodyBytes or of unknown length, costs far more while it is read
// than a small one (D45): up to three copies in the page cache, and the buffers
// of a connection that is busy. LargeInFlightPerGiB per GiB of memory, between
// MinLargeInFlight and MaxLargeInFlight; FallbackLargeInFlight when the memory is
// unknown.
const (
	LargeInFlightPerGiB   = 128
	MinLargeInFlight      = 16
	MaxLargeInFlight      = 16384
	FallbackLargeInFlight = 256
)

// A checked body leaves its transaction before it waits for the backend (D44).
// Up to WaitingMemoryBodyBytes it waits in memory, what is larger waits in a
// temp file. Every waiting request has WaitingOverheadBytes on top: measured
// 105 KiB on HTTP/1.1 (four goroutines, buffers of two connections, the request
// and socket memory), rounded up. A body on disk leaves memory only in part: up
// to WaitingSendBytes of it lie in the send queue of the backend's socket, charged
// to the container, for as long as the backend reads nothing (measured 335 KiB per
// socket on Linux with default buffers, D45).
const (
	WaitingMemoryBodyBytes = int64(128) << 10
	WaitingOverheadBytes   = int64(128) << 10
	WaitingSendBytes       = int64(384) << 10
)

// waf.body.max_waiting_bytes when schild.yaml does not set it: 1/WaitingShare
// of the memory, between MinWaitingBytes and MaxWaitingBytes;
// FallbackWaitingBytes when the memory is unknown.
const (
	WaitingShare         = 4
	MinWaitingBytes      = int64(32) << 20
	MaxWaitingBytes      = int64(16) << 30
	FallbackWaitingBytes = int64(256) << 20
)

// waf.requests.max_waiting when schild.yaml does not set it: a quarter of the
// memory in units of WaitingOverheadBytes, between MinWaitingRequests and
// MaxWaitingRequests; FallbackWaitingRequests when the memory is unknown. A
// quarter, not half, since D60: the connections of D46 take the other quarter of
// the same memory, and both full at once ended a 2 GiB container.
const (
	WaitingRequestShare     = 4
	MinWaitingRequests      = 256
	MaxWaitingRequests      = 1 << 20
	FallbackWaitingRequests = 4096
)

// waf.connections.max_open when schild.yaml does not set it: a quarter of the
// memory in units of ConnBytes, between MinConns and MaxConns; FallbackConns when
// the memory is unknown (D46, a quarter since D60). ConnBytes is a unit, no bound: an HTTP/2 connection with
// TLS costs about 50 KiB with the collector at its limit and about 80 KiB with room
// in the heap, HTTP/1.1 about 30 and 50 KiB.
const (
	ConnBytes     = int64(64) << 10
	ConnShare     = 4
	MinConns      = 1024
	MaxConns      = 1 << 20
	FallbackConns = 8192
)

// H2MaxStreams is how many requests one HTTP/2 connection may run at once
// (SETTINGS_MAX_CONCURRENT_STREAMS, D60). Go's default is 250; browsers open far
// fewer, nginx allows 128. A client over it gets REFUSED_STREAM and repeats.
const H2MaxStreams = 100

// ConnEvictMinAgeS is how long a connection must have been idle before a new one
// may take its place (D46). It bounds what a client at its limit can make the
// gateway do: limit / ConnEvictMinAgeS new TLS handshakes per second, 409 at the
// default. A browser needs far less for its next request.
const ConnEvictMinAgeS = 5

// Memory pressure (D45), in percent of the container memory held by what the
// kernel cannot drop at once (MemoryStat.Held). Above PressureBodiesPercent no
// body is admitted, above PressureRequestsPercent no request.
const (
	PressureBodiesPercent   = 70
	PressureRequestsPercent = 85
)

// Levels of Pressure.
const (
	PressureNone     = 0
	PressureBodies   = 1
	PressureRequests = 2
	// PressureUnknown is a value of the gauge, never a level: no brake is running,
	// because there is no limit from the cgroup or memory.stat cannot be read (D46).
	// A gauge at 0 would look like calm.
	PressureUnknown = -1
)

// MultipartForm is the only media type that counts as a multipart body.
const MultipartForm = "multipart/form-data"

// Refusal codes (schild_hard_limit_rejects_total{code}).
const (
	CodeClientShare = "body_client_share"
	// CodeWaitingShare: a client or network holds its share of memory in bodies
	// waiting for the backend (D44). The cause is what already waits there, not
	// the size or number of the bodies being sent.
	CodeWaitingShare = "body_waiting_share"
	CodeBusy         = "body_busy"
	CodeRawTooLarge  = "raw_body_too_large"
	// CodeRequestShare: a client or network holds its share of the requests
	// waiting for the backend (D45). CodeRequestBusy: the gateway holds
	// max_waiting of them, or its memory is under pressure.
	CodeRequestShare = "request_waiting_share"
	CodeRequestBusy  = "request_busy"
	// CodeBodyRead: reading the body failed and the client is still there.
	CodeBodyRead = "body_read_error"
	// CodeTooLarge is the existing limit code of request_body_limit_bytes.
	CodeTooLarge = "body_too_large"
	// CodeClientGone: the client left while its body was read. No answer, no
	// incident, no event, only a counter (E10).
	CodeClientGone = "client_gone"
)

// FailClosedBusy is the key of TrafficCounters.fail_closed_by and the reason
// of the waiting page decision (waitingpage.ReasonBodyBusy). The request limits
// of D45 use it too: the class says the gateway refused to take more on, the
// limit code says which limit.
const FailClosedBusy = "body_busy"

// Traffic classes of a refused body.
const (
	ClassRejectedLimit = "rejected_limit"
	ClassFailClosed    = "fail_closed"
)

// Scopes of a refusal.
const (
	ScopeClient  = "client"
	ScopeNetwork = "network"
	ScopeGateway = "gateway"
)

// Body classes. A class selects a limit and nothing else: every class is
// inspected as before. The header is the client's word, so a class may only
// ever make a request stricter, never exempt it (E8).
const (
	BodyText      = "text"
	BodyMultipart = "multipart"
	BodyRaw       = "raw"
)

// Measure-only rate (E2): the rule of a later enforcement, measured now.
const (
	RateWindowS      = 30
	RateMinBytesPerS = 1024
)

// Temp space of bodies under storage.path (E11, D38).
const TempDir = "tmp"

// TempFilePrefixes are the file names the gateway removes from TempDir at
// start, before the first request.
var TempFilePrefixes = []string{"body", "crzmp"}

// Prometheus names on the metrics port. No UI, no API, no metric id (D41).
const (
	PromBodiesInFlight     = "schild_bodies_in_flight"     // gauge
	PromBodyBytesInFlight  = "schild_body_bytes_in_flight" // gauge
	PromBodySpoolBytes     = "schild_body_spool_bytes"     // gauge
	PromBodiesWaiting      = "schild_bodies_waiting"       // gauge
	PromBodyWaitingBytes   = "schild_body_waiting_bytes"   // gauge
	PromBodiesAborted      = "schild_bodies_aborted_total" // counter{reason}
	PromBodiesBelowMinRate = "schild_bodies_below_min_rate_total"
	PromBodyReadSeconds    = "schild_body_read_seconds"          // histogram
	PromBodyRate           = "schild_body_rate_bytes_per_second" // histogram
	PromRequestsWaiting    = "schild_requests_waiting"           // gauge, D45
	PromMemoryPressure     = "schild_memory_pressure"            // gauge, D45: 0, 1, 2; D46: -1 no brake
	PromConnections        = "schild_connections_open"           // gauge, D46
	PromConnsRefused       = "schild_connections_refused_total"  // counter{scope}, D46
	PromConnsEvicted       = "schild_connections_evicted_total"  // counter{scope}, D46
	PromLocalRulesReloads  = "schild_local_rules_reloads_total"  // counter{result}, D46
)

// Results of schild_local_rules_reloads_total (D46).
const (
	ReloadApplied   = "applied"
	ReloadUnchanged = "unchanged"
	ReloadRefused   = "refused"
)

// Reasons of schild_bodies_aborted_total. AbortTooSlow stays 0 until the
// minimum rate is enforced (P1).
const (
	AbortTooSlow    = "too_slow"
	AbortClientGone = "client_gone"
	AbortTooLarge   = "too_large"
	AbortShare      = "share"
	AbortWaiting    = "waiting"
	AbortBusy       = "busy"
)

// Histogram buckets (upper bounds, +Inf added by Prometheus).
var (
	ReadSecondsBuckets = []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600}
	RateBuckets        = []float64{256, 512, 1024, 2048, 4096, 16384, 65536, 262144, 1048576, 10485760}
)

// Limits are the effective limits of one gateway.
type Limits struct {
	MaxPerClient     int   `json:"max_per_client"`
	MaxPerNetwork    int   `json:"max_per_network"`
	MaxInFlight      int   `json:"max_in_flight"`
	MaxInFlightBytes int64 `json:"max_in_flight_bytes"`
	// D44: waiting bytes (Waiting). 0 applies no limit.
	MaxWaitingBytesPerClient  int64 `json:"max_waiting_bytes_per_client,omitempty"`
	MaxWaitingBytesPerNetwork int64 `json:"max_waiting_bytes_per_network,omitempty"`
	MaxWaitingBytes           int64 `json:"max_waiting_bytes,omitempty"`
	// D45: large bodies being read (Large). 0 applies no limit.
	MaxLargeInFlight int `json:"max_large_in_flight,omitempty"`
}

// State is what runs at the moment of a decision. Client and Network count
// bodies being read for the client key and its network; InFlight every body
// being read; InFlightBytes the held bytes (Held) of the gateway. The waiting
// bytes (Waiting) are those of the client key, its network and the gateway.
type State struct {
	Client             int   `json:"client"`
	Network            int   `json:"network"`
	InFlight           int   `json:"in_flight"`
	InFlightBytes      int64 `json:"in_flight_bytes"`
	ClientWaitingBytes int64 `json:"client_waiting_bytes,omitempty"`
	NetWaitingBytes    int64 `json:"network_waiting_bytes,omitempty"`
	WaitingBytes       int64 `json:"waiting_bytes,omitempty"`
	// Pressure is the level of Pressure at this moment (D45).
	Pressure int `json:"pressure,omitempty"`
	// LargeInFlight counts the large bodies being read, Large says that this body
	// is one (D45).
	LargeInFlight int  `json:"large_in_flight,omitempty"`
	Large         bool `json:"large,omitempty"`
}

// Large reports whether a declared length makes a body large: over
// WaitingMemoryBodyBytes, or unknown (D45).
func Large(declared int64) bool { return declared < 0 || declared > WaitingMemoryBodyBytes }

// Decision is the result of Admit.
type Decision struct {
	Admitted bool `json:"admitted"`
	// Code, Status, Scope and Class are null for an admitted body.
	Code   *string `json:"code"`
	Status *int    `json:"status"`
	Scope  *string `json:"scope"`
	Class  *string `json:"class"`
	// FailClosed is the fail_closed_by key of a 503, RetryAfter the seconds of
	// a 429; a 503 takes its Retry-After from the waiting page decision.
	FailClosed *string `json:"fail_closed"`
	RetryAfter *int    `json:"retry_after"`
}

// Shared reports whether a client of netClass never gets a 429 (D29): they
// are answered 503, with the waiting page for a document navigation (E5).
func Shared(netClass string) bool {
	return netClass == "cgnat" || netClass == "mobile" || netClass == "tor"
}

// Factor of the client and network limits for a net class. tor is shared, but
// keeps the plain limits, like the evaluation slots.
func Factor(netClass string) int {
	if netClass == "cgnat" || netClass == "mobile" {
		return SharedFactor
	}
	return 1
}

// Admit decides on one request with a body, before any WAF work. clientKnown
// is false without a valid client address: only the gateway-wide limits apply.
// draw is a uniform random value per response. Client and network come first,
// so that a client over its share gets its own answer whatever else is full.
func Admit(l Limits, s State, netClass string, clientKnown bool, draw uint32) Decision {
	f := Factor(netClass)
	switch {
	case clientKnown && s.Client >= l.MaxPerClient*f:
		return share(CodeClientShare, netClass, ScopeClient, draw)
	case clientKnown && over(s.ClientWaitingBytes, l.MaxWaitingBytesPerClient*int64(f)):
		return share(CodeWaitingShare, netClass, ScopeClient, draw)
	case clientKnown && s.Network >= l.MaxPerNetwork*f:
		return share(CodeClientShare, netClass, ScopeNetwork, draw)
	case clientKnown && over(s.NetWaitingBytes, l.MaxWaitingBytesPerNetwork*int64(f)):
		return share(CodeWaitingShare, netClass, ScopeNetwork, draw)
	case s.InFlight >= l.MaxInFlight, s.InFlightBytes >= l.MaxInFlightBytes, over(s.WaitingBytes, l.MaxWaitingBytes), s.Pressure >= PressureBodies,
		s.Large && l.MaxLargeInFlight > 0 && s.LargeInFlight >= l.MaxLargeInFlight:
		return refused(CodeBusy, ScopeGateway)
	}
	return Decision{Admitted: true}
}

// RequestLimits are the limits of requests waiting for the backend (D45). A
// request counts from the admission until it ended, with or without a body, in
// every mode, also for a request the allowlist lets past the WAF.
type RequestLimits struct {
	MaxPerClient  int `json:"max_waiting_per_client"`
	MaxPerNetwork int `json:"max_waiting_per_network"`
	Max           int `json:"max_waiting"`
}

// RequestState is what runs at the moment of a decision: the waiting requests
// of the client key, of its network and of the gateway, and the memory pressure.
type RequestState struct {
	Client   int `json:"client_waiting"`
	Network  int `json:"network_waiting"`
	Waiting  int `json:"waiting"`
	Pressure int `json:"pressure,omitempty"`
}

// AdmitRequest decides on one request, before any WAF work. clientKnown is false
// without a valid client address: only the gateway-wide limit applies. Client and
// network come first, so that a client over its share gets its own answer
// whatever else is full.
func AdmitRequest(l RequestLimits, s RequestState, netClass string, clientKnown bool, draw uint32) Decision {
	f := Factor(netClass)
	switch {
	case clientKnown && s.Client >= l.MaxPerClient*f:
		return share(CodeRequestShare, netClass, ScopeClient, draw)
	case clientKnown && s.Network >= l.MaxPerNetwork*f:
		return share(CodeRequestShare, netClass, ScopeNetwork, draw)
	case s.Waiting >= l.Max, s.Pressure >= PressureRequests:
		return refused(CodeRequestBusy, ScopeGateway)
	}
	return Decision{Admitted: true}
}

// RequestLimit is the effective max_waiting: the configured value, else derived
// from memoryBytes (0: unknown).
func RequestLimit(configured int, memoryBytes int64) int {
	if configured > 0 {
		return configured
	}
	if memoryBytes <= 0 {
		return FallbackWaitingRequests
	}
	return int(min(max(memoryBytes/(WaitingRequestShare*WaitingOverheadBytes), MinWaitingRequests), MaxWaitingRequests))
}

// MemoryStat holds the lines of memory.stat of the container that the kernel
// cannot give back at once (D46). Slab is slab_reclaimable + slab_unreclaimable:
// most of the reclaimable part is the inodes and dentries of open sockets, which
// the kernel cannot drop while the socket lives: a third of the slab still stood at
// the kills by open connections. Clean page cache is not here: the
// kernel drops it on its own, and a healthy gateway often stands at 100 % of
// memory.current with hundreds of MiB of it.
type MemoryStat struct {
	Anon        int64 `json:"anon"`
	Sock        int64 `json:"sock"`
	Slab        int64 `json:"slab"`
	KernelStack int64 `json:"kernel_stack"`
	PageTables  int64 `json:"pagetables"`
	Shmem       int64 `json:"shmem"`
	Dirty       int64 `json:"file_dirty"`
	Writeback   int64 `json:"file_writeback"`
}

// Held is what counts against the container limit without a way out: the kernel
// kills the process when this reaches the limit.
func (s MemoryStat) Held() int64 { return s.Anon + s.Outside() }

// Outside is the part of Held the Go runtime knows nothing of.
func (s MemoryStat) Outside() int64 {
	return s.Sock + s.Slab + s.KernelStack + s.PageTables + s.Shmem + s.Dirty + s.Writeback
}

// ConnLimits are the limits of open connections (D46). 0 applies no limit.
type ConnLimits struct {
	MaxPerClient  int `json:"max_per_client"`
	MaxPerNetwork int `json:"max_per_network"`
	Max           int `json:"max_open"`
}

// ConnState is what is open at the moment of a decision: the connections of the
// peer's client key, of its network and of the gateway, and for each of the three
// whether one of them is idle long enough to give up its place.
type ConnState struct {
	Client      int  `json:"client"`
	Network     int  `json:"network"`
	Open        int  `json:"open"`
	ClientIdle  bool `json:"client_idle,omitempty"`
	NetworkIdle bool `json:"network_idle,omitempty"`
	OpenIdle    bool `json:"open_idle,omitempty"`
}

// ConnDecision is the result of AdmitConnection. Evict and Refused are null or the
// scope that was full; Evict names the scope the oldest idle connection is taken
// from, so that the new one fits. One place is enough: a connection frees its
// place in all three scopes.
type ConnDecision struct {
	Admitted bool    `json:"admitted"`
	Evict    *string `json:"evict"`
	Refused  *string `json:"refused"`
}

// AdmitConnection decides on one accepted connection, before any TLS work.
// peerKnown is false without a usable peer address. proxy says that the peer is a
// trusted proxy: its address is not the client, so the client and network limits
// do not apply to it, only the limit of the gateway. A full scope first takes the
// place of its oldest idle connection and refuses only when all of them are busy:
// a client behind one address with many idle browsers does not lock itself out.
func AdmitConnection(l ConnLimits, s ConnState, netClass string, peerKnown, proxy bool) ConnDecision {
	f, perPeer := Factor(netClass), peerKnown && !proxy
	switch {
	case perPeer && connsFull(s.Client, l.MaxPerClient*f):
		return connFull(ScopeClient, s.ClientIdle)
	case perPeer && connsFull(s.Network, l.MaxPerNetwork*f):
		return connFull(ScopeNetwork, s.NetworkIdle)
	case connsFull(s.Open, l.Max):
		return connFull(ScopeGateway, s.OpenIdle)
	}
	return ConnDecision{Admitted: true}
}

func connFull(scope string, idle bool) ConnDecision {
	if idle {
		return ConnDecision{Admitted: true, Evict: &scope}
	}
	return ConnDecision{Refused: &scope}
}

// connsFull applies a limit of connections: 0 applies none.
func connsFull(n, limit int) bool { return limit > 0 && n >= limit }

// ConnLimit is the effective max_open: the configured value, else derived from
// memoryBytes (0: unknown).
func ConnLimit(configured int, memoryBytes int64) int {
	if configured > 0 {
		return configured
	}
	if memoryBytes <= 0 {
		return FallbackConns
	}
	return int(min(max(memoryBytes/(ConnShare*ConnBytes), MinConns), MaxConns))
}

// Pressure is the level for held bytes of memoryBytes (0: unknown, no level).
func Pressure(memoryBytes, held int64) int {
	switch {
	case memoryBytes <= 0:
		return PressureNone
	case held >= memoryBytes/100*PressureRequestsPercent:
		return PressureRequests
	case held >= memoryBytes/100*PressureBodiesPercent:
		return PressureBodies
	}
	return PressureNone
}

// How reading a body ended, when it failed (body-limits.md section 4).
const (
	ReadEndClientLeft = "client_left" // the connection or stream is gone
	ReadEndTimeout    = "timeout"     // read_body or read_body_idle ended the read
	ReadEndError      = "error"       // anything else
)

// ReadEndCode is the limit code of a failed read. A client that left and one
// that stalled get the same code: a radio gap is no attack (E10, D45), so neither
// writes an incident or an event, whatever the mode.
func ReadEndCode(end string) string {
	if end == ReadEndError {
		return CodeBodyRead
	}
	return CodeClientGone
}

// Outcomes of a failed read in schild_requests_total and the hourly summary.
// OutcomeClientGone is not a decision of the gateway: nobody blocked anything, the
// client left or stalled (D46, takes back that part of D45).
const (
	OutcomeBlocked    = "blocked"
	OutcomeClientGone = "client_gone"
)

// ReadEndOutcome is the outcome a failed read counts as.
func ReadEndOutcome(end string) string {
	if ReadEndCode(end) == CodeClientGone {
		return OutcomeClientGone
	}
	return OutcomeBlocked
}

// over applies a limit of waiting bytes: 0 applies none.
func over(n, limit int64) bool { return limit > 0 && n >= limit }

func share(code, netClass, scope string, draw uint32) Decision {
	if Shared(netClass) {
		return refused(code, scope)
	}
	status, class := 429, ClassRejectedLimit
	retry := 5 + int(draw%4)
	return Decision{Code: &code, Status: &status, Scope: &scope, Class: &class, RetryAfter: &retry}
}

func refused(code, scope string) Decision {
	status, class, busy := 503, ClassFailClosed, FailClosedBusy
	return Decision{Code: &code, Status: &status, Scope: &scope, Class: &class, FailClosed: &busy}
}

// CheckRequests is the semantic check of waf.requests: the limits nest. max 0:
// derived. It returns "" or the problem.
func CheckRequests(perClient, perNetwork, maxWaiting int) string {
	switch {
	case perClient > perNetwork:
		return "waf.requests.max_waiting_per_client above max_waiting_per_network"
	case maxWaiting != 0 && perNetwork > maxWaiting:
		return "waf.requests.max_waiting_per_network above max_waiting"
	}
	return ""
}

// CheckConnections is the semantic check of waf.connections: the limits nest.
// maxOpen 0: derived. It returns "" or the problem.
func CheckConnections(perClient, perNetwork, maxOpen int) string {
	switch {
	case perClient > perNetwork:
		return "waf.connections.max_per_client above max_per_network"
	case maxOpen != 0 && perNetwork > maxOpen:
		return "waf.connections.max_per_network above max_open"
	}
	return ""
}

// CheckConfig is the semantic check of schild.yaml: the limits nest, and one
// multipart body of the largest size fits max_in_flight_bytes. maxInFlight and
// maxWaiting 0: derived. It returns "" or the problem.
func CheckConfig(perClient, perNetwork, maxInFlight int, maxBytes, bodyLimit, waitClient, waitNetwork, maxWaiting int64) string {
	switch {
	case waitClient > waitNetwork:
		return "waf.body.max_waiting_bytes_per_client above max_waiting_bytes_per_network"
	case maxWaiting != 0 && waitNetwork > maxWaiting:
		return "waf.body.max_waiting_bytes_per_network above max_waiting_bytes"
	case perClient > perNetwork:
		return "waf.body.max_per_client above max_per_network"
	case maxInFlight != 0 && perNetwork > maxInFlight:
		return "waf.body.max_per_network above max_in_flight"
	case maxBytes < bodyLimit*MultipartWeight:
		return "waf.body.max_in_flight_bytes below twice request_body_limit_bytes"
	}
	return ""
}

// InFlightLimit is the effective max_in_flight: the configured value, else
// derived from memoryBytes (0: unknown).
func InFlightLimit(configured int, memoryBytes int64) int {
	if configured > 0 {
		return configured
	}
	if memoryBytes <= 0 {
		return FallbackInFlight
	}
	if memoryBytes >= (MaxInFlight/InFlightPerGiB)*gib {
		return MaxInFlight
	}
	return max(int(memoryBytes*InFlightPerGiB/gib), MinInFlight)
}

// LargeInFlightLimit is the effective max_large_in_flight: the configured value,
// else derived from memoryBytes (0: unknown).
func LargeInFlightLimit(configured int, memoryBytes int64) int {
	if configured > 0 {
		return configured
	}
	if memoryBytes <= 0 {
		return FallbackLargeInFlight
	}
	if memoryBytes >= (MaxLargeInFlight/LargeInFlightPerGiB)*gib {
		return MaxLargeInFlight
	}
	return max(int(memoryBytes*LargeInFlightPerGiB/gib), MinLargeInFlight)
}

// WaitingLimit is the effective max_waiting_bytes: the configured value, else
// derived from memoryBytes (0: unknown).
func WaitingLimit(configured, memoryBytes int64) int64 {
	if configured > 0 {
		return configured
	}
	if memoryBytes <= 0 {
		return FallbackWaitingBytes
	}
	return min(max(memoryBytes/WaitingShare, MinWaitingBytes), MaxWaitingBytes)
}

// WaitsInMemory reports whether a checked body of n bytes waits in memory.
func WaitsInMemory(n int64) bool { return n <= WaitingMemoryBodyBytes }

// Waiting is what a checked body of n bytes counts while it waits for the
// backend: the overhead of the request, and the body when it waits in memory,
// else what of it the send queue of the backend's socket can hold (D45).
func Waiting(n int64) int64 {
	if WaitsInMemory(n) {
		return WaitingOverheadBytes + n
	}
	return WaitingOverheadBytes + min(n, WaitingSendBytes)
}

// Classify returns the class of a Content-Type header value. The media type is
// read as Coraza and mime.ParseMediaType read it: before the first ";", with
// Unicode case and space rules. Coraza parses a body as multipart only for
// multipart/form-data, and CRS reads any other subtype as text, so no other
// multipart type is a multipart body here. Coraza's own test is a prefix: a
// media type that only starts with multipart/form-data is parsed as multipart
// there and stays raw here, which is stricter, never freer.
func Classify(contentType string) string {
	mt, _, _ := strings.Cut(contentType, ";")
	mt = strings.TrimSpace(strings.ToLower(mt))
	switch {
	case mt == MultipartForm:
		return BodyMultipart
	case strings.HasPrefix(mt, "multipart/"):
		return BodyRaw
	case mt == "application/x-www-form-urlencoded", mt == "application/json", mt == "application/xml",
		strings.HasPrefix(mt, "text/"), strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return BodyText
	}
	return BodyRaw
}

// ClassifyValues returns the class of all Content-Type values of a request.
// Several values are raw: rules read every value, Coraza's parser and most
// backends only the first, so none of them can be trusted to name the parser.
func ClassifyValues(values []string) string {
	if len(values) > 1 {
		return BodyRaw
	}
	if len(values) == 1 {
		return Classify(values[0])
	}
	return Classify("")
}

// LimitOf is the size limit of a body of class: request_body_limit_bytes, for
// raw bodies at most raw_body_limit_bytes.
func LimitOf(class string, rawLimit, bodyLimit int64) int64 {
	if class == BodyRaw && rawLimit < bodyLimit {
		return rawLimit
	}
	return bodyLimit
}

// CheckSize applies the size limits to bytes (the declared length, or what
// was read so far): "" when it fits, else CodeTooLarge or CodeRawTooLarge.
func CheckSize(class string, n, rawLimit, bodyLimit int64) string {
	switch {
	case n > bodyLimit:
		return CodeTooLarge
	case n > LimitOf(class, rawLimit, bodyLimit):
		return CodeRawTooLarge
	}
	return ""
}

// Held is what read bytes of a body of class count against
// max_in_flight_bytes.
func Held(class string, read int64) int64 {
	if class == BodyMultipart {
		return read * MultipartWeight
	}
	return read
}

// Arrival is one read of a body: Bytes at TMS, milliseconds after the start.
type Arrival struct {
	TMS   int64 `json:"t_ms"`
	Bytes int64 `json:"bytes"`
}

// RateResult is the measurement of one body up to a moment.
type RateResult struct {
	// Windows holds the rate of each complete window in bytes per second
	// (rounded down): one histogram sample each.
	Windows []int64 `json:"windows"`
	// BelowMin is true when a complete window fell under RateMinBytesPerS: a
	// later enforcement would have ended this body. It counts once per body.
	BelowMin bool `json:"below_min"`
	// FirstBelow is the index of the first such window, null without one.
	FirstBelow *int `json:"first_below"`
}

// Rate measures a body with fixed windows of RateWindowS from its start, up to
// endMS (the end of the body, or now while it is open). A partial window gives
// no sample: a short body says nothing about the rule, and the last bytes of a
// finished body do not count as slow. A stall gives windows of 0.
func Rate(arrivals []Arrival, endMS int64) RateResult {
	windowMS := int64(RateWindowS) * 1000
	n := endMS / windowMS
	sum := make([]int64, n)
	for _, a := range arrivals {
		if i := a.TMS / windowMS; a.TMS >= 0 && i < n {
			sum[i] += a.Bytes
		}
	}
	r := RateResult{Windows: make([]int64, n)}
	for i, b := range sum {
		r.Windows[i] = b / RateWindowS
		if r.Windows[i] < RateMinBytesPerS && !r.BelowMin {
			j := i
			r.BelowMin, r.FirstBelow = true, &j
		}
	}
	return r
}

// MaxInputBytes bounds a vector input.
const MaxInputBytes = 64 << 10

// vector inputs: body-limits.schema.json.
type vectorInput struct {
	Op             string    `json:"op"`
	Limits         Limits    `json:"limits"`
	State          State     `json:"state"`
	NetClass       string    `json:"net_class"`
	ClientKnown    bool      `json:"client_known"`
	JitterDraw     uint32    `json:"jitter_draw"`
	Configured     int       `json:"configured"`
	MemoryBytes    int64     `json:"memory_bytes"`
	ContentType    string    `json:"content_type"`
	ContentTypes   []string  `json:"content_types"`
	Bytes          int64     `json:"bytes"`
	RawLimitBytes  int64     `json:"raw_limit_bytes"`
	BodyLimitBytes int64     `json:"body_limit_bytes"`
	Arrivals       []Arrival `json:"arrivals"`
	EndMS          int64     `json:"end_ms"`
	ConfiguredB    int64     `json:"configured_bytes"`
	// D45
	RequestLimits RequestLimits `json:"request_limits"`
	RequestState  RequestState  `json:"request_state"`
	HeldBytes     int64         `json:"held_bytes"`
	End           string        `json:"end"`
	// D46
	ConnLimits ConnLimits `json:"conn_limits"`
	ConnState  ConnState  `json:"conn_state"`
	PeerKnown  bool       `json:"peer_known"`
	Proxy      bool       `json:"proxy"`
	Stat       MemoryStat `json:"stat"`
}

// SizeResult of the op size.
type SizeResult struct {
	Class      string  `json:"class"`
	LimitBytes int64   `json:"limit_bytes"`
	Code       *string `json:"code"`
	Status     *int    `json:"status"`
	Held       int64   `json:"held_bytes"`
}

// WaitingResult of the op waiting.
type WaitingResult struct {
	InMemory     bool  `json:"in_memory"`
	WaitingBytes int64 `json:"waiting_bytes"`
}

// WaitingLimitResult of the op waiting_limit.
type WaitingLimitResult struct {
	MaxWaitingBytes int64 `json:"max_waiting_bytes"`
}

// LargeInFlightResult of the op large_in_flight.
type LargeInFlightResult struct {
	MaxLargeInFlight int `json:"max_large_in_flight"`
}

// RequestLimitResult of the op request_limit.
type RequestLimitResult struct {
	MaxWaiting int `json:"max_waiting"`
}

// PressureResult of the op pressure.
type PressureResult struct {
	Pressure int `json:"pressure"`
}

// ReadEndResult of the op read_end.
type ReadEndResult struct {
	Code     string `json:"code"`
	Incident bool   `json:"incident"`
}

// ReadOutcomeResult of the op read_outcome.
type ReadOutcomeResult struct {
	Outcome string `json:"outcome"`
}

// ConnLimitResult of the op conn_limit.
type ConnLimitResult struct {
	MaxOpen int `json:"max_open"`
}

// HeldResult of the op held.
type HeldResult struct {
	HeldBytes    int64 `json:"held_bytes"`
	OutsideBytes int64 `json:"outside_bytes"`
}

// InFlightResult of the op in_flight.
type InFlightResult struct {
	MaxInFlight int `json:"max_in_flight"`
}

// RunVector checks one body-limits vector and returns its result.
func RunVector(raw []byte) (any, error) {
	if len(raw) > MaxInputBytes {
		return nil, contract.Errf(contract.CodeOversize, "%d bytes > %d", len(raw), MaxInputBytes)
	}
	v, err := jsonx.ParseObject(raw)
	if err != nil {
		return nil, contract.Errf(contract.CodeMalformed, "%v", err)
	}
	if err := schema.Validate(schema.BodyLimits, v); err != nil {
		return nil, err
	}
	var in vectorInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, contract.Errf(contract.CodeSchema, "%v", err)
	}
	switch in.Op {
	case "admit":
		return Admit(in.Limits, in.State, in.NetClass, in.ClientKnown, in.JitterDraw), nil
	case "in_flight":
		return InFlightResult{InFlightLimit(in.Configured, in.MemoryBytes)}, nil
	case "size":
		class := Classify(in.ContentType)
		if in.ContentTypes != nil {
			class = ClassifyValues(in.ContentTypes)
		}
		r := SizeResult{Class: class, LimitBytes: LimitOf(class, in.RawLimitBytes, in.BodyLimitBytes), Held: Held(class, in.Bytes)}
		if c := CheckSize(class, in.Bytes, in.RawLimitBytes, in.BodyLimitBytes); c != "" {
			status := 413
			r.Code, r.Status = &c, &status
		}
		return r, nil
	case "waiting":
		return WaitingResult{WaitsInMemory(in.Bytes), Waiting(in.Bytes)}, nil
	case "waiting_limit":
		return WaitingLimitResult{WaitingLimit(in.ConfiguredB, in.MemoryBytes)}, nil
	case "large_in_flight":
		return LargeInFlightResult{LargeInFlightLimit(in.Configured, in.MemoryBytes)}, nil
	case "request_admit":
		return AdmitRequest(in.RequestLimits, in.RequestState, in.NetClass, in.ClientKnown, in.JitterDraw), nil
	case "request_limit":
		return RequestLimitResult{RequestLimit(in.Configured, in.MemoryBytes)}, nil
	case "pressure":
		return PressureResult{Pressure(in.MemoryBytes, in.HeldBytes)}, nil
	case "read_end":
		code := ReadEndCode(in.End)
		return ReadEndResult{code, code != CodeClientGone}, nil
	case "read_outcome":
		return ReadOutcomeResult{ReadEndOutcome(in.End)}, nil
	case "conn_admit":
		return AdmitConnection(in.ConnLimits, in.ConnState, in.NetClass, in.PeerKnown, in.Proxy), nil
	case "conn_limit":
		return ConnLimitResult{ConnLimit(in.Configured, in.MemoryBytes)}, nil
	case "held":
		return HeldResult{in.Stat.Held(), in.Stat.Outside()}, nil
	default: // rate
		return Rate(in.Arrivals, in.EndMS), nil
	}
}
