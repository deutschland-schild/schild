package main

// schild logcheck: access logs vs. the hard limits, before schild goes in
// front of a site (concept 23 §2, DECISIONS D23).

import (
	"os"

	"github.com/deutschland-schild/schild/gateway/internal/app"
	"github.com/deutschland-schild/schild/gateway/internal/logcheck"
)

func cmdLogcheck(args []string) error {
	return logcheck.Main(args, os.Stdin, os.Stdout, os.Stderr, func(path string) (logcheck.Limits, error) {
		cfg, _, err := app.LoadConfig(path)
		if err != nil {
			return logcheck.Limits{}, err
		}
		l := logcheck.DefaultLimits()
		l.BodyBytes = int64(cfg.WAF.RequestBodyLimitBytes)
		l.EvalTimeoutMS = cfg.WAF.EvalTimeoutMS
		return l, nil
	})
}
