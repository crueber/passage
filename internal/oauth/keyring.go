package oauth

import (
	"crypto/rsa"
	"sort"
	"time"
)

// SigningKey is one RSA key in the OIDC signing keyring.
//
// The private key is unexported so it cannot be serialised into a template or
// a JSON response by accident: only KID and the timestamps are for display.
// Callers outside the package (the admin UI) only need the metadata.
type SigningKey struct {
	// KID is the base64url SHA-256 of the public key's DER encoding — the
	// derivation Passage has always used. It is stable for the life of the key
	// and is what id_token headers and the JWKS advertise.
	KID string
	// CreatedAt is when the key was added to the keyring. The newest key signs.
	CreatedAt time.Time
	// RetiredAt is set when the key stops being served and accepted. A retired
	// key can be deleted; a non-retired key cannot.
	RetiredAt *time.Time

	privateKey *rsa.PrivateKey
}

// Retired reports whether the key has been retired.
func (k *SigningKey) Retired() bool {
	return k != nil && k.RetiredAt != nil
}

// PublicKey returns the RSA public half used to verify signatures.
func (k *SigningKey) PublicKey() *rsa.PublicKey {
	if k == nil || k.privateKey == nil {
		return nil
	}
	return &k.privateKey.PublicKey
}

// Keyring is an immutable snapshot of the signing keys, newest first.
//
// A new snapshot is built whenever the store changes and installed atomically
// on the Service, so a rotation is visible to every request without locking
// reads. Keys are never dropped implicitly: retiring or deleting a key is the
// only way it leaves the ring.
type Keyring struct {
	keys []*SigningKey
}

// newKeyring sorts keys newest first and rejects a ring that cannot sign.
// The order is stable, so keys created within the same second keep the
// insertion order reported by the store (newest row first).
func newKeyring(keys []*SigningKey) (*Keyring, error) {
	if len(keys) == 0 {
		return nil, ErrNoSigningKey
	}

	sorted := make([]*SigningKey, len(keys))
	copy(sorted, keys)
	for _, k := range sorted {
		if k == nil || k.KID == "" || k.privateKey == nil {
			return nil, ErrNoSigningKey
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
	})

	ring := &Keyring{keys: sorted}
	if ring.Current() == nil {
		// Every key is retired: there is nothing to sign with, which would take
		// OIDC down. Refuse the snapshot instead of serving a broken issuer.
		return nil, ErrNoSigningKey
	}
	return ring, nil
}

// Current returns the newest non-retired key, which is the signing key.
func (k *Keyring) Current() *SigningKey {
	if k == nil {
		return nil
	}
	for _, key := range k.keys {
		if !key.Retired() {
			return key
		}
	}
	return nil
}

// Active returns every non-retired key, newest first. These are the keys
// served in the JWKS and accepted for signature verification.
func (k *Keyring) Active() []*SigningKey {
	if k == nil {
		return nil
	}
	active := make([]*SigningKey, 0, len(k.keys))
	for _, key := range k.keys {
		if !key.Retired() {
			active = append(active, key)
		}
	}
	return active
}

// All returns every key in the ring, newest first, retired keys included.
func (k *Keyring) All() []*SigningKey {
	if k == nil {
		return nil
	}
	all := make([]*SigningKey, len(k.keys))
	copy(all, k.keys)
	return all
}

// ByKID returns the non-retired key with the given kid. A retired or unknown
// kid is not found: its tokens are no longer accepted.
func (k *Keyring) ByKID(kid string) (*SigningKey, bool) {
	if k == nil || kid == "" {
		return nil, false
	}
	for _, key := range k.keys {
		if key.KID == kid {
			if key.Retired() {
				return nil, false
			}
			return key, true
		}
	}
	return nil, false
}
