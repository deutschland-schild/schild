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
		{"private address", "cluster: {enabled: true, listen: \"10.0.0.2:8790\"}\n", ""},
		{"loopback", "cluster: {enabled: true, listen: \"127.0.0.1:8790\"}\n", ""},
		{"no listen", "cluster: {enabled: true}\n", "cluster.listen"},
		{"public address", "cluster: {enabled: true, listen: \"203.0.113.5:8790\"}\n", "no private or loopback"},
		{"public address allowed", "cluster: {enabled: true, listen: \"203.0.113.5:8790\", allow_public_listen: true}\n", ""},
		{"every address without advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", allow_public_listen: true}\n", "cluster.advertise"},
		{"every address with advertise", "cluster: {enabled: true, listen: \"0.0.0.0:8790\", allow_public_listen: true, advertise: \"10.0.0.2:8790\"}\n", ""},
		{"by configuration", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /etc/schild/cluster.secret, peers: [\"10.0.0.1:8790\", \"10.0.0.2:8790\"]}\n", ""},
		{"peers without the secret", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", peers: [\"10.0.0.1:8790\"]}\n", "secret_file"},
		{"peer is a host name", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x, peers: [\"web-1:8790\"]}\n", "schema"},
		{"peer is every address", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", secret_file: /x, peers: [\"0.0.0.0:8790\"]}\n", "cluster.peers"},
		{"host name", "cluster: {enabled: true, listen: \"web-1:8790\"}\n", "schema"},
		{"unknown key", "cluster: {enabled: true, listen: \"10.0.0.2:8790\", store: valkey}\n", "schema"},
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
