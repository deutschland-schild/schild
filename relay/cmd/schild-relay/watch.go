package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deutschland-schild/schild/contract"
	"github.com/deutschland-schild/schild/contract/keys"
	"github.com/deutschland-schild/schild/contract/msg"
	"github.com/deutschland-schild/schild/contract/stream"
	"github.com/deutschland-schild/schild/contract/verify"
	"github.com/deutschland-schild/schild/relay/upstream"
)

// watch follows a relay or lab feed like a client would and prints one JSON
// line per event with the verification result (debugging and test lab).
//
//	schild-relay watch -url https://relay-1:7480 -keys lab-a=op-a:test-lab-a=ed25519:...,... [-k 3]
//	schild-relay watch -url ... -test-keys lab-a,lab-b,lab-c        (non-release builds only)
func watch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	url := fs.String("url", "", "relay or lab feed base URL")
	keyList := fs.String("keys", "", "trusted lab keys: lab=operator:keyid=ed25519:<b64>, comma separated")
	testKeys := fs.String("test-keys", "", "TEST ONLY key names (lab-a,lab-b,...) instead of -keys")
	k := fs.Int("k", 3, "operators needed for bundles and withdrawals (floor 2)")
	channel := fs.String("channel", "schild-main", "expected bundle_id")
	dur := fs.Duration("for", 0, "stop after this long (0 = until interrupted)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" {
		return errors.New("watch needs -url")
	}
	trust := keys.NewTrustStore()
	if *testKeys != "" {
		ts, err := testTrust(strings.Split(*testKeys, ","))
		if err != nil {
			return err
		}
		trust = ts
	}
	for _, item := range strings.Split(*keyList, ",") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		labOp, kid, ok := strings.Cut(item, ":")
		lab, op, ok2 := strings.Cut(labOp, "=")
		keyid, pubs, ok3 := strings.Cut(kid, "=")
		if !ok || !ok2 || !ok3 {
			return fmt.Errorf("bad -keys entry %q", item)
		}
		pub, err := keys.ParsePublicKey(pubs)
		if err != nil {
			return err
		}
		if err := trust.Add(keys.TrustedKey{KeyID: keyid, Public: pub, Lab: lab, Operator: op,
			Purposes: []contract.Purpose{contract.PurposeRules, contract.PurposeCheckpoint}}); err != nil {
			return err
		}
	}
	client, err := upstream.HTTPClient()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	fresh := stream.NewFreshness(0)
	enc := json.NewEncoder(os.Stdout)
	vctx := &verify.Context{Trust: trust, Threshold: *k, Channel: *channel, SkipState: true}
	sub := &upstream.Subscriber{Base: *url, Client: client, Name: "watch", OnEvent: func(ev upstream.Event) {
		out := map[string]any{"type": ev.Event.Type, "id": ev.Event.ID}
		env := []byte(ev.Event.Envelope)
		if ev.Event.Type == stream.TypeHeartbeat {
			env = ev.Event.Checkpoint
			out["relay"] = ev.Event.Relay
		}
		if ev.Event.Ref != nil {
			out["ref"] = ev.Event.Ref
			b, err := upstream.Fetch(ctx, client, *url, ev.Event.Ref)
			if err != nil {
				out["error"] = err.Error()
				enc.Encode(out)
				return
			}
			env = b
		}
		vctx.Now = time.Now()
		res, err := verify.Signed(verify.StreamKind(ev.Event.Type), env, vctx)
		out["verified"] = err == nil
		if err != nil {
			out["error"] = err.Error()
		} else {
			out["operators"] = res.Operators
			switch v := res.Value.(type) {
			case *msg.Checkpoint:
				at, _ := msg.ParseTime(v.IssuedAt)
				fresh.Observe(at)
				out["lab"], out["seq"], out["bundle_version"], out["withdrawal_seq"] = v.Lab, v.Seq, v.Bundle.Version, v.WithdrawalSeq
			case *msg.Bundle:
				out["version"], out["rules"] = v.Version, len(v.Rules)
			case *msg.Withdrawal:
				out["seq"], out["scope"], out["up_to_version"] = v.Seq, v.Scope, v.UpToVersion
			}
		}
		out["frozen"] = fresh.Frozen(time.Now())
		enc.Encode(out)
	}}
	sub.Run(ctx)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil
	}
	return nil
}
