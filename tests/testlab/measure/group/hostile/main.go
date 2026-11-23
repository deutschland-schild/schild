// Command hostile is the protocol-level adversary of the MVP-27 measurement.
// It speaks the mesh of contracts/cluster.md (TLS 1.3, HTTP/2, self-signed
// Ed25519 certificates) from the text of the contract alone; it imports
// nothing of schild. Standard library only.
//
//	hostile id    -key FILE                       node id and public key of a node key
//	hostile call  -addr A -path P [-key FILE | -random | -nocert] [-body JSON] [-timeout S]
//	hostile sign  -key FILE                       record JSON on stdin, signed record on stdout
//	hostile serve -key FILE -listen A -records FILE   answer /mesh/v0/sync with the records of FILE
//	hostile gone  [-key FILE | -random] -listen A -group G   answer every mesh call 410 with X-Schild-Group G
//	                                                         (a "you were removed" from a key that is no member)
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "hostile:", err)
		os.Exit(1)
	}
}

func loadKey(file string, random bool) ed25519.PrivateKey {
	if random {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		die(err)
		return k
	}
	raw, err := os.ReadFile(file)
	die(err)
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	die(err)
	if len(seed) != ed25519.SeedSize {
		die(fmt.Errorf("%s: want %d bytes of seed, got %d", file, ed25519.SeedSize, len(seed)))
	}
	return ed25519.NewKeyFromSeed(seed)
}

// nodeID: "n-" and the first 16 bytes, hex, of SHA-256 over "schild-node:" and the public key (section 1).
func nodeID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(append([]byte("schild-node:"), pub...))
	return "n-" + hex.EncodeToString(h[:16])
}

func cert(key ed25519.PrivateKey) tls.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "schild-node"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	die(err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// signingInput follows section 2: each part as its length in decimal, a space, the bytes and a space.
func signingInput(rec map[string]any) []byte {
	var b bytes.Buffer
	part := func(p []byte) { b.WriteString(strconv.Itoa(len(p))); b.WriteByte(' '); b.Write(p); b.WriteByte(' ') }
	str := func(k string) string { s, _ := rec[k].(string); return s }
	num := func(k string) string {
		switch v := rec[k].(type) {
		case json.Number:
			return v.String()
		}
		return "0"
	}
	deleted := "0"
	if d, _ := rec["deleted"].(bool); d {
		deleted = "1"
	}
	data, _ := base64.StdEncoding.DecodeString(str("data"))
	part([]byte("schild-cluster-record-v1"))
	part([]byte(num("v")))
	part([]byte(str("group")))
	part([]byte(str("class")))
	part([]byte(str("id")))
	part([]byte(str("origin")))
	part([]byte(num("seq")))
	part([]byte(num("hlc")))
	part([]byte(deleted))
	part([]byte(str("expires")))
	part(data)
	return b.Bytes()
}

func main() {
	if len(os.Args) < 2 {
		die(fmt.Errorf("usage: hostile id|call|sign|serve"))
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	keyFile := fs.String("key", "", "node key file (64 hex characters of the seed)")
	random := fs.Bool("random", false, "use a fresh key that is no member")
	nocert := fs.Bool("nocert", false, "show no client certificate")
	addr := fs.String("addr", "", "mesh address")
	path := fs.String("path", "/mesh/v0/sync", "path")
	body := fs.String("body", "{}", "JSON body")
	timeout := fs.Float64("timeout", 8, "seconds")
	listen := fs.String("listen", "", "listen address")
	records := fs.String("records", "", "file with a JSON array of records to serve")
	group := fs.String("group", "", "gone: the group id named in X-Schild-Group")
	die(fs.Parse(os.Args[2:]))

	switch os.Args[1] {
	case "id":
		k := loadKey(*keyFile, *random)
		pub := k.Public().(ed25519.PublicKey)
		fmt.Printf("{\"id\":%q,\"public_key\":%q}\n", nodeID(pub), base64.StdEncoding.EncodeToString(pub))
	case "sign":
		k := loadKey(*keyFile, *random)
		dec := json.NewDecoder(os.Stdin)
		dec.UseNumber()
		var rec map[string]any
		die(dec.Decode(&rec))
		rec["sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(k, signingInput(rec)))
		out, _ := json.Marshal(rec)
		fmt.Println(string(out))
	case "call":
		cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
		if !*nocert {
			cfg.Certificates = []tls.Certificate{cert(loadKey(*keyFile, *random))}
		}
		c := &http.Client{Timeout: time.Duration(*timeout * float64(time.Second)), Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true}}
		resp, err := c.Post("https://"+*addr+*path, "application/json", strings.NewReader(*body))
		if err != nil {
			out, _ := json.Marshal(map[string]any{"status": 0, "error": err.Error()})
			fmt.Println(string(out))
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		out, _ := json.Marshal(map[string]any{"status": resp.StatusCode, "proto": resp.Proto, "body": string(raw)})
		fmt.Println(string(out))
	case "serve":
		k := loadKey(*keyFile, false)
		me := nodeID(k.Public().(ed25519.PublicKey))
		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			in, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
			if r.URL.Path != "/mesh/v0/sync" {
				fmt.Printf("{\"path\":%q,\"answer\":404}\n", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			var req struct {
				Vector map[string]int64 `json:"vector"`
			}
			_ = json.Unmarshal(in, &req)
			var all []map[string]any
			if raw, err := os.ReadFile(*records); err == nil {
				dec := json.NewDecoder(bytes.NewReader(raw))
				dec.UseNumber()
				_ = dec.Decode(&all)
			}
			// Hand over every record of the file the caller has not seen by its vector. A record
			// marked "_always" is handed over on every call (a replay).
			send := []map[string]any{}
			covered := map[string]int64{}
			for _, rec := range all {
				origin, _ := rec["origin"].(string)
				seq, _ := rec["seq"].(json.Number).Int64()
				always, _ := rec["_always"].(bool)
				if seq <= req.Vector[origin] && !always {
					continue
				}
				out := map[string]any{}
				for key, v := range rec {
					if !strings.HasPrefix(key, "_") {
						out[key] = v
					}
				}
				send = append(send, out)
				if seq > covered[origin] {
					covered[origin] = seq
				}
			}
			if len(send) == 0 {
				time.Sleep(time.Second)
			}
			peer := ""
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
					peer = nodeID(pub)
				}
			}
			fmt.Printf("{\"path\":%q,\"caller\":%q,\"sent\":%d,\"request\":%s}\n", r.URL.Path, peer, len(send), strings.TrimSpace(string(in)))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"records": send, "covered": covered, "vector": covered, "more": false})
		})
		srv := &http.Server{Addr: *listen, Handler: mux, TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert(k)}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		}}
		fmt.Printf("{\"serving\":%q,\"as\":%q}\n", *listen, me)
		die(srv.ListenAndServeTLS("", ""))
	case "gone":
		k := loadKey(*keyFile, *random)
		me := nodeID(k.Public().(ed25519.PublicKey))
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 4<<20))
			peer := ""
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				if pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
					peer = nodeID(pub)
				}
			}
			fmt.Printf("{\"path\":%q,\"caller\":%q,\"answer\":410}\n", r.URL.Path, peer)
			if *group != "" {
				w.Header().Set("X-Schild-Group", *group)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"code":"removed"}`))
		})
		srv := &http.Server{Addr: *listen, Handler: h, TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert(k)}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		}}
		fmt.Printf("{\"serving\":%q,\"as\":%q}\n", *listen, me)
		die(srv.ListenAndServeTLS("", ""))
	default:
		die(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
