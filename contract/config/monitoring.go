package config

import "github.com/deutschland-schild/schild/contract"

// Monitoring is the v0.4 (MVP-21, D33) traffic and server monitoring of the
// built-in dashboard. Aggregates only; nothing derived from an IP address is
// written. Without the section monitoring is on with the defaults.
type Monitoring struct {
	Enabled    *bool          `json:"enabled"`
	Host       *bool          `json:"host"`
	Mounts     []string       `json:"mounts,omitempty"`
	Interfaces []string       `json:"interfaces,omitempty"`
	Keep       MonitoringKeep `json:"keep"`
	// Requests is the v0.5 (MVP-22, D35) request ring.
	Requests Requests `json:"requests"`
}

// Requests is the v0.5 (MVP-22, D35) request ring: single requests in 10
// min segment files, kept min(keep_hours, retention.raw_ip_days x 24) hours
// (D66), the oldest first gone above max_size_mb.
type Requests struct {
	Enabled   *bool `json:"enabled"`
	KeepHours int   `json:"keep_hours"`
	MaxSizeMB int   `json:"max_size_mb"`
}

// Defaults and caps of monitoring.requests.
const (
	DefaultRequestsKeepHours = 720 // D66: follow retention.raw_ip_days
	DefaultRequestsMaxSizeMB = 512
	MaxRequestsKeepHours     = 720
)

// RequestsOn reports whether the request ring runs (default: when
// monitoring runs).
func (m *Monitoring) RequestsOn() bool {
	return m.On() && (m.Requests.Enabled == nil || *m.Requests.Enabled)
}

// MonitoringKeep is the ring size of each fixed resolution.
type MonitoringKeep struct {
	TenSecondsHours int `json:"ten_seconds_hours"`
	MinuteHours     int `json:"minute_hours"`
	TenMinuteDays   int `json:"ten_minute_days"`
}

// Defaults of the monitoring section (schild.schema.json).
const (
	DefaultKeepTenSecondsHours = 6
	DefaultKeepMinuteHours     = 48
	DefaultKeepTenMinuteDays   = 14
)

// On reports whether monitoring runs (default true).
func (m *Monitoring) On() bool { return m.Enabled == nil || *m.Enabled }

// HostOn reports whether host files (/proc, /sys) are sampled (default true).
func (m *Monitoring) HostOn() bool { return m.On() && (m.Host == nil || *m.Host) }

func (m *Monitoring) defaults() {
	if m.Enabled == nil {
		m.Enabled = boolp(true)
	}
	if m.Host == nil {
		m.Host = boolp(true)
	}
	orInt(&m.Keep.TenSecondsHours, DefaultKeepTenSecondsHours)
	orInt(&m.Keep.MinuteHours, DefaultKeepMinuteHours)
	orInt(&m.Keep.TenMinuteDays, DefaultKeepTenMinuteDays)
	orInt(&m.Requests.KeepHours, DefaultRequestsKeepHours)
	orInt(&m.Requests.MaxSizeMB, DefaultRequestsMaxSizeMB)
}

// check: a coarser resolution never covers less time than a finer one; the
// request ring needs the monitoring counters (v0.5).
func (m *Monitoring) check() error {
	k := m.Keep
	if k.TenSecondsHours > k.MinuteHours || k.MinuteHours > k.TenMinuteDays*24 {
		return contract.Errf(contract.CodeConfig, "monitoring.keep: ten_seconds_hours <= minute_hours <= ten_minute_days*24 required")
	}
	if e := m.Requests.Enabled; e != nil && *e && m.Enabled != nil && !*m.Enabled {
		return contract.Errf(contract.CodeConfig, "monitoring.requests.enabled needs monitoring.enabled")
	}
	return nil
}

// Bots is the v0.5 (MVP-22, D35) bot verification. Observation only.
type Bots struct {
	Verify      BotsVerify `json:"verify"`
	RangesFetch *bool      `json:"ranges_fetch"`
}

// BotsVerify switches the address checks of claimed bots.
type BotsVerify struct {
	Ranges *bool `json:"ranges"` // default true
	FCrDNS *bool `json:"fcrdns"` // default false
}

// RangesOn reports whether shipped range snapshots are checked.
func (b *Bots) RangesOn() bool { return b.Verify.Ranges == nil || *b.Verify.Ranges }

// FCrDNSOn reports whether reverse lookups are made (sends addresses to the
// resolver).
func (b *Bots) FCrDNSOn() bool { return b.Verify.FCrDNS != nil && *b.Verify.FCrDNS }

// FetchOn reports whether ranges are fetched from the operators directly.
func (b *Bots) FetchOn() bool { return b.RangesFetch == nil || *b.RangesFetch }

func (b *Bots) defaults() {
	if b.Verify.Ranges == nil {
		b.Verify.Ranges = boolp(true)
	}
	if b.Verify.FCrDNS == nil {
		b.Verify.FCrDNS = boolp(false)
	}
	if b.RangesFetch == nil {
		b.RangesFetch = boolp(true) // D67
	}
}
