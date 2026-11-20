//go:build !release

package main

import (
	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/vectors"
)

// v0.4 (MVP-21, D33): traffic and server monitoring. Appended after the
// MVP-19 vectors so every earlier vector keeps its number.

func genSiteConfigV04Monitoring(g *gen) {
	const c = "config/schild"
	ctx := vectors.Context{}
	add := func(valid bool, code contract.Code, name, desc string, m map[string]any) {
		g.add(c, name, valid, code, desc, ctx, mustJSON(m), m)
	}
	with := func(base func() map[string]any, mon map[string]any) map[string]any {
		m := base()
		m["monitoring"] = mon
		return m
	}

	add(true, "", "monitoring-defaults", "v0.4 MVP-21: empty monitoring section, on with 10 s for 6 h, 1 min for 48 h, 10 min for 14 d.", with(siteConfig, map[string]any{}))
	add(true, "", "monitoring-full", "v0.4 MVP-21: explicit mounts and interfaces, longer rings, standalone gateway.", with(standaloneConfig, map[string]any{
		"enabled": true, "host": true,
		"mounts":     []string{"/", "/var/lib/schild", "/srv/www"},
		"interfaces": []string{"eth0", "ens3", "wg0"},
		"keep":       map[string]any{"ten_seconds_hours": 24, "minute_hours": 168, "ten_minute_days": 90},
	}))
	add(true, "", "monitoring-off", "v0.4 MVP-21: monitoring switched off.", with(standaloneConfig, map[string]any{"enabled": false}))
	add(true, "", "monitoring-traffic-only", "v0.4 MVP-21: no host files (e.g. a container without /proc of the host), shortest rings in order.", with(siteConfig, map[string]any{
		"host": false, "keep": map[string]any{"ten_seconds_hours": 1, "minute_hours": 24, "ten_minute_days": 1},
	}))
	add(true, "", "monitoring-keep-equal", "v0.4 MVP-21: equal coverage of 10 s and 1 min is allowed.", with(siteConfig, map[string]any{
		"keep": map[string]any{"ten_seconds_hours": 12, "minute_hours": 12},
	}))

	for _, f := range []struct {
		name string
		code contract.Code
		mon  map[string]any
		desc string
	}{
		{"monitoring-unknown-key", contract.CodeSchema, map[string]any{"enabled": true, "export": true}, "v0.4 MVP-21: unknown monitoring key (the export is MVP-20)."},
		{"monitoring-enabled-string", contract.CodeSchema, map[string]any{"enabled": "yes"}, "v0.4 MVP-21: enabled is a boolean."},
		{"monitoring-host-number", contract.CodeSchema, map[string]any{"host": 1}, "v0.4 MVP-21: host is a boolean."},
		{"monitoring-ten-seconds-zero", contract.CodeSchema, map[string]any{"keep": map[string]any{"ten_seconds_hours": 0}}, "v0.4 MVP-21: ten_seconds_hours at least 1."},
		{"monitoring-ten-seconds-too-long", contract.CodeSchema, map[string]any{"keep": map[string]any{"ten_seconds_hours": 25}}, "v0.4 MVP-21: ten_seconds_hours at most 24."},
		{"monitoring-minute-too-long", contract.CodeSchema, map[string]any{"keep": map[string]any{"minute_hours": 169}}, "v0.4 MVP-21: minute_hours at most 168 (7 days)."},
		{"monitoring-ten-minute-too-long", contract.CodeSchema, map[string]any{"keep": map[string]any{"ten_minute_days": 91}}, "v0.4 MVP-21: ten_minute_days at most 90."},
		{"monitoring-keep-unknown", contract.CodeSchema, map[string]any{"keep": map[string]any{"one_second_minutes": 5}}, "v0.4 MVP-21: the resolutions are fixed; no other ring."},
		{"monitoring-mount-relative", contract.CodeSchema, map[string]any{"mounts": []string{"var/lib"}}, "v0.4 MVP-21: mounts are absolute paths."},
		{"monitoring-mount-duplicate", contract.CodeSchema, map[string]any{"mounts": []string{"/", "/"}}, "v0.4 MVP-21: each mount once."},
		{"monitoring-too-many-mounts", contract.CodeSchema, map[string]any{"mounts": []string{"/m01", "/m02", "/m03", "/m04", "/m05", "/m06", "/m07", "/m08", "/m09", "/m10", "/m11", "/m12", "/m13", "/m14", "/m15", "/m16", "/m17"}}, "v0.4 MVP-21: at most 16 mounts (bounded series)."},
		{"monitoring-mounts-empty", contract.CodeSchema, map[string]any{"mounts": []string{}}, "v0.4 MVP-21: an empty list is not 'none'; leave the key out for the default."},
		{"monitoring-interface-too-long", contract.CodeSchema, map[string]any{"interfaces": []string{"enp0s31f6-very-long"}}, "v0.4 MVP-21: interface names have at most 15 characters (IFNAMSIZ)."},
		{"monitoring-interface-slash", contract.CodeSchema, map[string]any{"interfaces": []string{"../eth0"}}, "v0.4 MVP-21: interface names never contain a slash."},
		{"monitoring-ten-seconds-above-minute", contract.CodeConfig, map[string]any{"keep": map[string]any{"ten_seconds_hours": 24, "minute_hours": 12}}, "v0.4 MVP-21: 10 s kept longer than 1 min (semantic check)."},
		{"monitoring-minute-above-ten-minute", contract.CodeConfig, map[string]any{"keep": map[string]any{"minute_hours": 168, "ten_minute_days": 2}}, "v0.4 MVP-21: 1 min kept longer than 10 min (semantic check)."},
		{"monitoring-default-minute-above-days", contract.CodeConfig, map[string]any{"keep": map[string]any{"ten_minute_days": 1}}, "v0.4 MVP-21: the default minute_hours 48 exceeds ten_minute_days 1 (defaults count)."},
	} {
		add(false, f.code, f.name, f.desc, with(siteConfig, f.mon))
	}
}
