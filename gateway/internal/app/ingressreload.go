package app

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/deutschland-schild/schild/contract/websites"
	"github.com/deutschland-schild/schild/gateway/internal/caddymod"
	"github.com/deutschland-schild/schild/gateway/internal/sites"
)

// runningIngress is the Caddyfile this gateway runs with, and the lock of
// its reloads. A reload and the stop of Caddy never overlap.
type runningIngress struct {
	mu      sync.Mutex
	json    []byte // the config Caddy runs; nil before the start and from the stop on
	storage string
}

func (r *runningIngress) started(ing *caddymod.Ingress) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.json, r.storage = ing.JSON, ing.StorageRoot
}

// stop waits for a reload that runs and refuses every later one.
func (r *runningIngress) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.json = nil
}

// IngressReload is the result of ReloadIngress.
type IngressReload struct {
	// Unchanged: the Caddyfile gives the config that runs, nothing was
	// loaded.
	Unchanged bool
	Websites  int
	Warnings  []string
}

// ReloadIngress reads the Caddyfile again and puts it in force without a
// restart (D106). Everything a start checks is checked before anything
// changes; on an error the running Caddyfile stays. Requests that run end
// with the Caddyfile they started with. The gate, its counters and the state
// of a group do not notice.
//
// What it refuses, because it needs a restart: other listen addresses,
// another certificate storage. And a change that takes a website, or a host
// of it, out of an access lock or a maintenance mode that is on.
func (a *App) ReloadIngress(force bool) (IngressReload, error) {
	return a.swapIngress(nil, force)
}

// MaxCaddyfile bounds the text LoadIngress takes.
const MaxCaddyfile = 8 << 20

// LoadIngress puts text in force as the Caddyfile of this gateway and writes
// it to ingress.caddyfile (`schild ingress load`, D106). It is ReloadIngress
// for a text that comes with the request: the same checks and refusals. The
// file is written after every check passed and before Caddy takes the
// config; when Caddy refuses it, the file is put back. Files the text
// imports are read on this host.
func (a *App) LoadIngress(text []byte, force bool) (IngressReload, error) {
	switch {
	case len(bytes.TrimSpace(text)) == 0:
		return IngressReload{}, errors.New("the Caddyfile is empty")
	case len(text) > MaxCaddyfile:
		return IngressReload{}, fmt.Errorf("the Caddyfile has %d bytes, more than %d", len(text), MaxCaddyfile)
	}
	return a.swapIngress(text, force)
}

func (a *App) swapIngress(body []byte, force bool) (IngressReload, error) {
	cfg := a.Config()
	if !cfg.CaddyIngress() {
		return IngressReload{}, errors.New("schild.yaml has no ingress.caddyfile, there is nothing to reload")
	}
	a.ingress.mu.Lock()
	defer a.ingress.mu.Unlock()
	if a.ingress.json == nil || a.Draining() {
		return IngressReload{}, errors.New("this gateway is starting or stopping")
	}
	res, err := a.reloadIngress(body, force)
	if err != nil {
		a.log.Error("ingress: the Caddyfile was not reloaded, the running one stays", "caddyfile", cfg.Ingress.Caddyfile, "sent", body != nil, "err", err)
		return res, err
	}
	for _, w := range res.Warnings {
		a.log.Warn("ingress: "+w, "caddyfile", cfg.Ingress.Caddyfile)
	}
	if res.Unchanged {
		a.log.Info("ingress: Caddyfile unchanged, nothing loaded", "caddyfile", cfg.Ingress.Caddyfile, "sent", body != nil)
		return res, nil
	}
	a.log.Info("ingress: Caddyfile reloaded", "caddyfile", cfg.Ingress.Caddyfile, "websites", res.Websites, "sent", body != nil)
	return res, nil
}

// reloadIngress checks and loads the Caddyfile: the file's text, or body when
// it is not nil, which then becomes the file's text.
func (a *App) reloadIngress(body []byte, force bool) (IngressReload, error) {
	cfg := a.Config()
	ing, err := ingressFor(cfg, a.dataDir, body)
	var res IngressReload
	if ing != nil {
		res.Warnings = ing.Check.Warnings
	}
	if err != nil {
		return res, err
	}
	// As at a start: a lost token must not stop a change of other websites,
	// so it is a warning of the command and not a refusal.
	for _, p := range caddymod.DNSTokenProblems(ing.JSON) {
		res.Warnings = append(res.Warnings, p+"; schild obtains or renews no certificate that needs this token. Fix it and run schild ingress reload -force")
	}
	if ing.StorageRoot != a.ingress.storage {
		return res, fmt.Errorf("the certificate storage changes from %s to %s, that needs a restart", a.ingress.storage, ing.StorageRoot)
	}
	if err := sameListeners(a.ingress.json, ing.JSON); err != nil {
		return res, err
	}
	cur := a.Sites.View()
	next := deriveWebsitesOf(cfg, a.dataDir, cur, body)
	if notDerived(next) {
		return res, fmt.Errorf("the websites cannot be read from the Caddyfile: %w", next.Err)
	}
	if next.Err != nil {
		res.Warnings = append(res.Warnings, "a Caddyfile block is no website (dropped), the other websites stay: "+next.Err.Error())
	}
	// The websites come from a second reading of the file: both have to be
	// the same file.
	if body == nil {
		if again, err := a.PrepareIngress(); err != nil || !bytes.Equal(again.JSON, ing.JSON) {
			return res, errors.New("the Caddyfile changed while it was read, run the reload again")
		}
	}
	// No lock is set between the check and the load.
	a.accessMu.Lock()
	defer a.accessMu.Unlock()
	if gone := a.lockedAndGone(cur, next); len(gone) > 0 {
		return res, fmt.Errorf("the access lock or the maintenance mode is on for %s, and the new Caddyfile would serve it without. A website is named by the first host of its block. End it first (schild lock off WEBSITE, the maintenance mode in the dashboard), or keep the block and its hosts", strings.Join(gone, ", "))
	}
	if ing.JSON, err = caddymod.BindWebsites(ing.JSON, next.Set.RouteWebsite); err != nil {
		return res, err
	}
	res.Websites = len(next.Websites())
	// Every check passed: the text becomes the file, so that a start reads
	// what runs.
	putBack := func() {}
	if body != nil {
		if putBack, err = replaceCaddyfile(cfg.Ingress.Caddyfile, body); err != nil {
			return res, fmt.Errorf("the Caddyfile passed the checks, and schild cannot write it to %s: %w. The user of schild needs write access to the file or its directory", cfg.Ingress.Caddyfile, err)
		}
	}
	if !force && bytes.Equal(ing.JSON, a.ingress.json) {
		res.Unchanged = true
		return res, nil
	}
	commit, rollback := a.Sites.Swap(next)
	if err := caddymod.Load(ing.JSON); err != nil {
		rollback()
		putBack()
		return res, fmt.Errorf("load Caddyfile %s: %w", cfg.Ingress.Caddyfile, err)
	}
	commit()
	a.ingress.json = ing.JSON
	return res, nil
}

// replaceCaddyfile writes text to path and returns a function that puts the
// old text back. A new file takes the place of the old one in one step where
// the directory allows it. Where it does not (a directory of root, a file
// mounted alone into a container), the file is written in place.
func replaceCaddyfile(path string, text []byte) (putBack func(), err error) {
	old, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(old, text) {
		return func() {}, nil
	}
	if err := writeFileInStep(path, text); err != nil {
		return nil, err
	}
	return func() { _ = writeFileInStep(path, old) }, nil
}

func writeFileInStep(path string, text []byte) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if tmp, err := os.CreateTemp(filepath.Dir(path), ".schild-caddyfile-*"); err == nil {
		_, werr := tmp.Write(text)
		if werr == nil {
			werr = tmp.Chmod(mode)
		}
		if werr == nil {
			werr = tmp.Sync()
		}
		if cerr := tmp.Close(); werr == nil {
			werr = cerr
		}
		if werr == nil {
			werr = os.Rename(tmp.Name(), path)
		}
		if werr == nil {
			return nil
		}
		_ = os.Remove(tmp.Name())
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// sameListeners refuses a config that listens elsewhere than the running one.
func sameListeners(running, next []byte) error {
	old, err := caddymod.ListenAddresses(running)
	if err != nil {
		return err
	}
	now, err := caddymod.ListenAddresses(next)
	if err != nil {
		return err
	}
	if slices.Equal(old, now) {
		return nil
	}
	return fmt.Errorf("the listen addresses change from %s to %s, that needs a restart", strings.Join(old, ", "), strings.Join(now, ", "))
}

// lockedAndGone returns what an access lock or a maintenance mode covers in
// cur and would not cover in next: a website that is gone or no longer runs
// through schild in full, or a host of it that another website serves.
// Called with accessMu held.
func (a *App) lockedAndGone(cur, next *sites.View) []string {
	if a.Access == nil {
		return nil
	}
	st := a.Access.State()
	ids := map[string]bool{}
	for id := range st.Entries {
		ids[id] = true
	}
	for id := range st.Maintenance {
		ids[id] = true
	}
	var out []string
	for id := range ids {
		old, ok := cur.Website(id)
		if !ok {
			continue // was not in force before either
		}
		if w, ok := next.Website(id); !ok || w.Protection != websites.Protected {
			out = append(out, id)
			continue
		}
		for _, h := range old.Hosts {
			now := ""
			if strings.ContainsAny(h, "*:") {
				now = next.Set.RouteWebsite([]string{h})
			} else {
				now = next.ID(h)
			}
			if now != "" && now != id {
				out = append(out, h+" of "+id)
			}
		}
	}
	sort.Strings(out)
	return out
}
