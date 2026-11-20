package reqring

import (
	"context"
	"math"
	"sort"
	"time"

	"github.com/deutschland-schild/schild/contract/bots"
	cm "github.com/deutschland-schild/schild/contract/monitoring"
	cr "github.com/deutschland-schild/schild/contract/requests"
)

// BotDirectory is what the bot overview needs from the bot engine
// (catalogue, range snapshots, switches, robots.txt fetches).
type BotDirectory interface {
	BotNames
	Bot(id uint16) *bots.Bot
	CatalogueVersion() string
	Ranges() []cr.RangeInfo
	Settings() cr.VerificationSettings
	// RobotsFetched reports whether the robots.txt of a website is known.
	RobotsFetched(site string) bool
}

// BotOverview answers getBotOverview: requests and bytes per bot category
// and per catalogue bot, last seen, verification counts and the robots.txt
// behaviour (observation only). dir may be nil (no catalogue loaded).
func (r *Ring) BotOverview(ctx context.Context, dir BotDirectory, site string, from, to time.Time) (cr.BotOverview, error) {
	sc, err := r.Bots(ctx, site, from, to)
	if err != nil {
		return cr.BotOverview{}, err
	}
	out := cr.BotOverview{From: FormatMs(from.UnixMilli()), To: FormatMs(to.UnixMilli()), Site: site, Ranges: []cr.RangeInfo{},
		Categories: []cr.CategoryEntry{}, Bots: []cr.BotEntry{}, SampleRate: sc.MinRate}
	if out.SampleRate <= 0 {
		out.SampleRate = 1
	}
	if dir != nil {
		out.CatalogueVersion = dir.CatalogueVersion()
		out.Verification = dir.Settings()
		if rs := dir.Ranges(); rs != nil {
			out.Ranges = rs
		}
	}
	if out.CatalogueVersion == "" {
		out.CatalogueVersion = "2000-01-01.0" // no catalogue loaded
	}
	for c, v := range sc.Categories {
		out.Categories = append(out.Categories, cr.CategoryEntry{Category: pick(cm.BotCategories, c), Requests: round(v[0]), BytesOut: round(v[1]), Bots: int(v[2])})
	}
	sort.Slice(out.Categories, func(i, j int) bool {
		if out.Categories[i].Requests != out.Categories[j].Requests {
			return out.Categories[i].Requests > out.Categories[j].Requests
		}
		return out.Categories[i].Category < out.Categories[j].Category
	})
	robotsKnown := dir != nil && (site == "" || dir.RobotsFetched(site))
	for id, b := range sc.Bots {
		e := cr.BotEntry{ID: botName(dir, id), Name: botName(dir, id), Category: pick(cm.BotCategories, b.Category), Requests: round(b.Requests),
			BytesOut: round(b.BytesOut), LastSeen: FormatMs(b.LastSeen),
			Verification: cr.BotCounts{Verified: round(b.Verif[VerifVerified]), Claimed: round(b.Verif[VerifClaimed] + b.Verif[VerifNone]),
				Mismatch: round(b.Verif[VerifMismatch]), UnknownStale: round(b.Verif[VerifUnknownStale])},
			Blocked: round(b.Blocked), WouldBlock: round(b.WouldBlock)}
		e.Operator = "unbekannt"
		if dir != nil {
			if cb := dir.Bot(id); cb != nil {
				e.ID, e.Name, e.Operator, e.Category = cb.ID, cb.Name, cb.Operator, cb.Category
				if cb.RobotsToken != "" {
					rb := &cr.Robots{Token: cb.RobotsToken, DisallowedRequests: round(b.Disallowed), Respects: "unclear"}
					if b.RobotsRead > 0 {
						s := FormatMs(b.RobotsRead)
						rb.ReadAt = &s
					}
					switch {
					case rb.DisallowedRequests > 0:
						rb.Respects = "no"
					case robotsKnown && rb.ReadAt != nil:
						rb.Respects = "yes"
					}
					e.Robots = rb
				}
			}
		}
		out.Bots = append(out.Bots, e)
	}
	sort.Slice(out.Bots, func(i, j int) bool {
		if out.Bots[i].Requests != out.Bots[j].Requests {
			return out.Bots[i].Requests > out.Bots[j].Requests
		}
		return out.Bots[i].ID < out.Bots[j].ID
	})
	return out, nil
}

func round(v float64) int64 { return int64(math.Round(v)) }
