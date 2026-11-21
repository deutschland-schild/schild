package cluster

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// A group can be set up by configuration alone: every node gets the same
// secret file and the addresses of the others, as a deployment writes them
// (Ansible, for example), and lets itself in at its start. No command and
// no code go from node to node by hand.
//
// The secret admits and does nothing else. From it comes one key pair, the
// group key; the group id is the hash of its public half. A node proves its
// place with the group key's signature over its own node key, carried in
// its member record. Every record is still signed by the node's own key, a
// removed node stays removed although it holds the secret, and the secret
// never travels.

// MinSecret is the least a group secret holds: 32 bytes, as
// `schild cluster secret` prints them in hex.
const MinSecret = 32

// ErrSecret is a group secret that is too short.
var ErrSecret = errors.New("cluster: the group secret is shorter than 32 bytes (make one with: schild cluster secret)")

// GroupKey derives the group key from the secret.
func GroupKey(secret []byte) (ed25519.PrivateKey, error) {
	if len(secret) < MinSecret {
		return nil, ErrSecret
	}
	seed := sha256.Sum256(append([]byte("schild-group-secret:"), secret...))
	return ed25519.NewKeyFromSeed(seed[:]), nil
}

func admitBytes(group string, node ed25519.PublicKey) []byte {
	return append([]byte("schild-admit:"+group+":"), node...)
}

// AdmitWith fills the admission of the node key into m and returns the id of
// the secret's group.
func (m *Member) AdmitWith(groupKey ed25519.PrivateKey, node ed25519.PublicKey) string {
	pub := groupKey.Public().(ed25519.PublicKey)
	group := GroupID(pub)
	m.AdmitKey = base64.StdEncoding.EncodeToString(pub)
	m.Admit = base64.StdEncoding.EncodeToString(ed25519.Sign(groupKey, admitBytes(group, node)))
	return group
}

// admitted reports whether the member carries the admission of this group:
// its admit key hashes to the group id and signed the member's node key.
func (m *Member) admitted(group string) bool {
	pub, err1 := base64.StdEncoding.Strict().DecodeString(m.AdmitKey)
	sig, err2 := base64.StdEncoding.Strict().DecodeString(m.Admit)
	node, ok := m.Key()
	if err1 != nil || err2 != nil || !ok || len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return GroupID(pub) == group && ed25519.Verify(pub, admitBytes(group, node), sig)
}
