// Command gen writes the CrowdSec Hub snapshot shipped in the schild binary
// (internal/hub/snapshot.json, schema schild.crowdsec_set/0.1): the items of
// the virtual patching collection at one hub commit, run through the same
// update rules as an update in the gateway, plus snapshot.NOTICE with the MIT
// text, the commit and the rules that did not convert. The hub is data here
// too: nothing of it is executed.
//
//	make crowdsec-snapshot            (from the repository root)
//	go run ./internal/hub/gen         (from gateway)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deutschland-schild/schild/contract/crowdsec"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/gateway/internal/hub"
)

const (
	commitURL = "https://api.github.com/repos/crowdsecurity/hub/commits/%s"
	userAgent = "schild-crowdsec-snapshot/0.1"
)

var commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func main() {
	out := flag.String("out", "internal/hub/snapshot.json", "snapshot file to write")
	commit := flag.String("commit", "", "hub commit (default: the head of master)")
	commitAt := flag.String("commit-at", "", "commit time; with -index, which works without network")
	index := flag.String("index", "", "use this .index.json file instead of downloading it; needs -commit and -commit-at")
	flag.Parse()
	if err := run(*out, *commit, *commitAt, *index); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func get(ctx context.Context, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, crowdsec.MaxIndexBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > crowdsec.MaxIndexBytes {
		return nil, fmt.Errorf("%s: above %d bytes", url, crowdsec.MaxIndexBytes)
	}
	return b, nil
}

// commitOf asks GitHub for a commit and when it was made (ref: a sha or master).
func commitOf(ctx context.Context, ref string) (sha, at string, err error) {
	b, err := get(ctx, fmt.Sprintf(commitURL, ref), "application/vnd.github+json")
	if err != nil {
		return "", "", err
	}
	var c struct {
		SHA    string `json:"sha"`
		Commit struct {
			Committer struct {
				Date string `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return "", "", err
	}
	t, err := time.Parse(time.RFC3339, c.Commit.Committer.Date)
	if err != nil {
		return "", "", fmt.Errorf("commit date: %w", err)
	}
	return c.SHA, msg.FormatTime(t), nil
}

func run(out, commit, commitAt, indexFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if indexFile != "" && (commit == "" || commitAt == "") {
		return fmt.Errorf("-index needs -commit and -commit-at")
	}
	if commitAt == "" {
		ref := commit
		if ref == "" {
			ref = "master"
		}
		var err error
		if commit, commitAt, err = commitOf(ctx, ref); err != nil {
			return err
		}
	}
	if !commitRe.MatchString(commit) {
		return fmt.Errorf("bad commit %q", commit)
	}
	var raw []byte
	var err error
	if indexFile != "" {
		raw, err = os.ReadFile(indexFile)
	} else {
		raw, err = get(ctx, fmt.Sprintf(crowdsec.PinnedURLFormat, commit), "")
	}
	if err != nil {
		return err
	}
	stamp := msg.FormatTime(time.Now().UTC().Truncate(time.Second))
	u := crowdsec.CheckIndex(raw, nil, crowdsec.DefaultLimits, stamp)
	if u.Outcome != "accepted" {
		return fmt.Errorf("index refused: %s", u.Code)
	}
	set, extra, err := hub.BuildSet(raw, u, u.Rules, commit, stamp)
	if err != nil {
		return err
	}
	set.HubCommitAt = commitAt
	b, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if _, err := crowdsec.ParseSet(b); err != nil {
		return fmt.Errorf("snapshot does not parse: %w", err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	var notice strings.Builder
	fmt.Fprintf(&notice, "CrowdSec Hub snapshot\n\nSource: https://github.com/crowdsecurity/hub\nCommit: %s (%s)\nIndex SHA-256: %s\nFetched: %s\n", commit, commitAt, u.IndexDigest, stamp)
	fmt.Fprintf(&notice, "Rules: %d selected, %d load, %d skipped, %d not selected\n\nSkipped rules:\n", len(u.Rules)+len(u.Skipped), len(u.Rules), len(u.Skipped), u.NotSelected)
	for _, sk := range u.Skipped {
		fmt.Fprintf(&notice, "  %s %s: %s\n", sk.Name, sk.Version, sk.Code)
	}
	notice.WriteString("\nThe rules are licensed under the MIT License; client/NOTICE carries the text.\n")
	if err := os.WriteFile(filepath.Join(filepath.Dir(out), "snapshot.NOTICE"), []byte(notice.String()), 0o644); err != nil {
		return err
	}
	fmt.Printf("commit %s: %d load, %d skipped (%d outside the set), %d not selected, %d bytes\n", commit, len(u.Rules), len(u.Skipped), len(extra), u.NotSelected, len(b))
	for _, sk := range u.Skipped {
		fmt.Printf("  skipped %s: %s\n", sk.Name, sk.Code)
	}
	return nil
}
