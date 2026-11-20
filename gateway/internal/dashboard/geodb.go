package dashboard

import (
	"encoding/json"

	"github.com/deutschland-schild/schild/gateway/internal/geo"
)

// NullTime is an optional timestamp that is sent as null when empty.
type NullTime string

// MarshalJSON writes null for the empty value.
func (t NullTime) MarshalJSON() ([]byte, error) {
	if t == "" {
		return []byte("null"), nil
	}
	return json.Marshal(string(t))
}

// geoDB is Overview.geo_db: "Geo-Daten: <provider>, Stand <built_at>" and,
// with a downloading provider (MVP-22), the refresh state. Nil when the
// bundled database is missing and nothing downloads.
func geoDB(s geo.Source) *GeoDB {
	if !s.Loaded && !s.Downloads {
		return nil
	}
	g := &GeoDB{Provider: s.Provider}
	if s.Loaded {
		g.Source, g.BuiltAt = s.Source, ts(s.BuiltAt)
		g.Databases, g.OptionalFields = s.Databases, s.OptionalFields
	}
	if s.Downloads {
		var r NullTime
		if !s.RefreshedAt.IsZero() {
			r = NullTime(ts(s.RefreshedAt))
		}
		g.RefreshedAt = &r
		if s.LastError != "" {
			g.LastError, g.LastErrorAt = s.LastError, ts(s.LastErrorAt)
		}
	}
	return g
}
