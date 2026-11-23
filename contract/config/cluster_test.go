package config

import (
	"strings"
	"testing"
)

func TestClusterConfig(t *testing.T) {
	base := "config_version: 0\nnode_name: web-1\nupstream: {url: \"http://127.0.0.1:8081\"}\n"
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"absent", "", ""},
		{"off needs nothing", "cluster: {enabled: false}\n", ""},
		{"private address", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x}\n", ""},
		{"loopback", "cluster: {enabled: true, listen: \"127.0.0.1:8790\", secret_file: /x}\n", ""},
		{"shared address space (overlay networks)", "cluster: {enabled: true, listen: \"100.101.102.103:8790\", secret_file: /x}\n", ""},
		{"just past the shared address space", "cluster: {enabled: true, listen: \"100.128.0.1:8790\", secret_file: /x}\n", "no private"},
		{"no listen", "cluster: {enabled: true, secret_file: /x}\n", "cluster.listen"},
		{"no secret file", "cluster: {enabled: true, listen: \"10.0.0.2:8790\"}\n", "cluster.secret_file"},
		{"public address", "cluster: {enabled: true, listen: \"203.0.113.5:8790\", secret_file: /x}\n", "no private"},
		{"public address allowed", "cluster: {enabled: true, listen: \"203.0.113.5:8790\", allow_public_listen: true, secret_file: /x}\n", ""},
		{"every address without advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", allow_public_listen: true, secret_file: /x}\n", "cluster.advertise"},
		{"every address with advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", allow_public_listen: true, advertise: \"10.0.0.2:8790\", secret_file: /x}\n", ""},
		{"every address with a private advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", advertise: \"10.0.0.2:8790\", secret_file: /x}\n", ""},
		{"every IPv6 address with a private advertise", "cluster: {enabled: true, listen: \"[::]:8790\", advertise: \"[fd00::2]:8790\", secret_file: /x}\n", ""},
		{"every address with a public advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", advertise: \"203.0.113.5:8790\", secret_file: /x}\n", "cluster.advertise 203.0.113.5:8790 is no private"},
		{"public advertise allowed", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", advertise: \"203.0.113.5:8790\", allow_public_listen: true, secret_file: /x}\n", ""},
		{"private listen, public advertise", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", advertise: \"203.0.113.5:8790\", secret_file: /x}\n", "no private"},
		{"by configuration", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /etc/schild/cluster.secret, peers: [\"10.0.0.1:8790\", \"10.0.0.2:8790\"]}\n", ""},
		{"peers without the secret", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", peers: [\"10.0.0.1:8790\"]}\n", "secret_file"},
		{"peer is a host name", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x, peers: [\"web-1:8790\"]}\n", "schema"},
		{"peer is every address", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x, peers: [\"0.0.0.0:8790\"]}\n", "IP:port"},
		{"host name", "cluster: {enabled: true, listen: \"web-1:8790\", secret_file: /x}\n", "schema"},
		{"unknown key", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x, store: valkey}\n", "schema"},
	}
	for _, c := range cases {
		s, err := ParseSite([]byte(base + c.yaml))
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.wantErr)
		case c.wantErr == "" && c.yaml != "" && strings.Contains(c.yaml, "enabled: true") && s.Cluster.Address() == "":
			t.Errorf("%s: no address", c.name)
		}
	}
}

// cluster.peers are written as a member record carries an address, so an
// IPv6 peer compares with the address of its member.
func TestClusterPeersAreCanonical(t *testing.T) {
	base := "config_version: 0\nnode_name: web-1\nupstream: {url: \"http://127.0.0.1:8081\"}\n"
	s, err := ParseSite([]byte(base + "cluster: {enabled: true, listen: \"[fd00::2]:8790\", secret_file: /x, peers: [\"[FD00:0:0::1]:8790\", \"[fd00:0:0:0:0:0:0:3]:8790\", \"10.0.0.4:8790\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"[fd00::1]:8790", "[fd00::3]:8790", "10.0.0.4:8790"}
	for i, p := range s.Cluster.Peers {
		if p != want[i] {
			t.Errorf("peer %d: %q, want %q", i, p, want[i])
		}
	}
}
