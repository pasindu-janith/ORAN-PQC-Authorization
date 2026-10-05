# Chunk 5A - Client library: configuration, identity, issuance

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** the foundations of the xApp-side OAuth client.

**Needs the cluster?** No.

> **Do not run `go build` yet.** The `xappclient` package is incomplete until Chunk 5C.
> Verify with `wc -l` only; the build happens at the end of 5C.


---

## A decision worth stating

The client library here is **already post-quantum aware**, even though the shim is not
deployed until Chunk 7. Two reasons:

1. Post-quantum support is a *configuration flag* in this design, not a separate code
   path. That is the design point worth defending, and splitting it would obscure it.
2. Stripping 1,700 lines down to a classical-only variant by hand would produce code
   that has never been compiled or tested.

With `PQ_MODE=false` the library behaves classically until Chunk 7 flips it.

## Three ideas to carry away

- **Methods A and B are one implementation.** `certBound` is parameterised by
  certificate lifetime and a key-rotation flag; the Keycloak client configuration for
  both is byte-identical. "Three methods" is really two code paths.
- **`Enroller.Enroll` builds the CSR with the CN of the *authenticating* certificate.**
  Combined with the CA ignoring the CSR subject, an xApp cannot request another
  identity from either direction.
- **`Issuer` is an interface.** That is the seam the post-quantum shim is inserted at in
  Chunk 8, via `SetIssuer`, with no call site changed. It is why post-quantum support
  does not fork the codebase.

## 5A.1 The shared binding-proof constants

Two constants in their own package, so the client and the shim cannot drift.

```bash
cat > ~/pqc-xapp-auth/internal/pqbind/pqbind.go <<'EOF'
// Package pqbind holds the constants shared by the post-quantum binding-transfer
// proof: the client builds it, the shim verifies it.
package pqbind

// ProofHeader carries the post-quantum binding proof on the upgrade request.
const ProofHeader = "X-PQ-Proof"

// ProofType is the "typ" of that proof JWT.
const ProofType = "pq-binding+jwt"
EOF
```


## 5A.2 Configuration

```bash
cat > ~/pqc-xapp-auth/xapp-client/config.go <<'EOF'
// Package xappclient is the xApp-side OAuth 2.0 client library for sender-constrained
// tokens. A caller selects the binding method by configuration (XAPP_METHOD) and uses
// the same Client interface regardless of method:
//
//	A  RFC 8705 certificate-bound token, long-term identity certificate
//	B  RFC 8705 certificate-bound token, ephemeral identity certificate (key rotated on every renewal)
//	C  RFC 9449 DPoP-bound token
//
// A and B are one implementation (certBound) parameterised by certificate lifetime and
// a key-rotation flag; Keycloak's client configuration for both is identical.
//
// With PQ_MODE=true the client additionally maintains a post-quantum credential
// (ML-DSA certificate, or ML-DSA DPoP key for method C) and upgrades every Keycloak
// token through the pq-shim into an ML-DSA-signed token bound to that credential.
// Keycloak remains on the classical credential because it supports neither ML-DSA nor
// ML-KEM; every other leg uses the post-quantum credential and the ML-KEM hybrid
// key exchange.
package xappclient

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
)

// Method selects the binding scheme.
type Method string

// Supported methods.
const (
	MethodLongTerm  Method = "A"
	MethodEphemeral Method = "B"
	MethodDPoP      Method = "C"
)

// PQIssuer names the service that issues the post-quantum access token.
type PQIssuer string

// Post-quantum issuers.
const (
	// PQIssuerShim: Keycloak issues a classical token and the pq-shim re-issues it
	// ML-DSA-signed and bound to the post-quantum credential. This is the only
	// option that works today, because no released Keycloak can sign with ML-DSA.
	PQIssuerShim PQIssuer = "shim"
	// PQIssuerKeycloak: the authorization server signs with ML-DSA itself and binds
	// the token to the post-quantum credential directly, so the shim leaves the
	// path entirely. Selecting it makes the client use the post-quantum credential
	// on the authorization-server leg as well, and refuse a token that is not
	// ML-DSA-signed. It is the exit condition for the shim, not a fallback: set it
	// only against an authorization server that advertises an ML-DSA signing key.
	PQIssuerKeycloak PQIssuer = "keycloak"
)

// RotationPolicy controls when Method B replaces its key pair.
type RotationPolicy string

// Rotation policies.
const (
	// RotateOnCertExpiry renews when the certificate approaches expiry (RenewBefore).
	RotateOnCertExpiry RotationPolicy = "cert-expiry"
	// RotateEveryToken renews the certificate before every token issuance.
	RotateEveryToken RotationPolicy = "every-token"
)

// Config configures a Client. ConfigFromEnv reads it from the environment.
type Config struct {
	Method      Method
	ClientID    string
	TokenURL    string
	Scope       string
	TrustBundle []string // PEM trust anchors for Keycloak, the RIC CA, the shim and peer xApps
	CAURL       string

	// Bootstrap credential (one-time) used for the first enrollment. Bootstrap, when
	// set, takes precedence over the file paths.
	BootstrapCert string
	BootstrapKey  string
	Bootstrap     *tls.Certificate

	IdentityDir  string        // where the operational credential is persisted ("" = memory only)
	KeyAlg       string        // identity key algorithm (EC-P256 default)
	CertLifetime time.Duration // requested operational certificate lifetime
	RenewBefore  time.Duration // renew when remaining lifetime <= RenewBefore (0 = 20% of lifetime)
	Rotation     RotationPolicy
	DNSNames     []string // requested SANs (must be granted by the bootstrap credential)

	DPoPAlg string // JWS alg for DPoP proofs (method C)

	// --- post-quantum --------------------------------------------------------
	PQEnabled        bool
	PQIssuer         PQIssuer // who issues the post-quantum token: the shim, or the AS itself
	PQShimURL        string   // base URL of the pq-shim (token upgrade + JWKS)
	PQKeyAlg         string   // ML-DSA parameter set for the identity certificate
	PQDPoPAlg        string   // ML-DSA parameter set for DPoP proofs (method C)
	PQCertLifetime   time.Duration
	PQBootstrapCert  string
	PQBootstrapKey   string
	PQBootstrap      *tls.Certificate
	PQIdentityDir    string
	PQKexOnly        bool // require the ML-KEM hybrid group on post-quantum legs
	PQProofValidity  time.Duration
	PQUpgradeTimeout time.Duration

	DialOverrides map[string]string
	HTTPTimeout   time.Duration
}

// DefaultLifetime returns the default certificate lifetime for a method.
func DefaultLifetime(m Method) time.Duration {
	if m == MethodEphemeral {
		return 15 * time.Minute
	}
	return 7 * 24 * time.Hour
}

// ConfigFromEnv reads the client configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	method := Method(strings.ToUpper(e.Str("XAPP_METHOD", "A")))
	c := Config{
		Method:           method,
		ClientID:         e.Req("XAPP_CLIENT_ID"),
		TokenURL:         e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:            e.Str("TOKEN_SCOPE", ""),
		TrustBundle:      e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:            e.Req("RIC_CA_URL"),
		BootstrapCert:    e.Str("BOOTSTRAP_CERT", ""),
		BootstrapKey:     e.Str("BOOTSTRAP_KEY", ""),
		IdentityDir:      e.Str("IDENTITY_DIR", ""),
		KeyAlg:           e.Str("IDENTITY_KEY_ALG", "EC-P256"),
		CertLifetime:     e.Dur("CERT_LIFETIME", DefaultLifetime(method)),
		RenewBefore:      e.Dur("RENEW_BEFORE", 0),
		Rotation:         RotationPolicy(e.Str("ROTATION_POLICY", string(RotateOnCertExpiry))),
		DNSNames:         e.List("SERVER_DNS_NAMES", nil),
		DPoPAlg:          e.Str("DPOP_ALG", "ES256"),
		PQEnabled:        e.Bool("PQ_MODE", false),
		PQIssuer:         PQIssuer(e.Str("PQ_ISSUER", string(PQIssuerShim))),
		PQShimURL:        e.Str("PQ_SHIM_URL", ""),
		PQKeyAlg:         e.Str("PQ_IDENTITY_KEY_ALG", "ML-DSA-65"),
		PQDPoPAlg:        e.Str("PQ_DPOP_ALG", "ML-DSA-44"),
		PQCertLifetime:   e.Dur("PQ_CERT_LIFETIME", 0),
		PQBootstrapCert:  e.Str("PQ_BOOTSTRAP_CERT", ""),
		PQBootstrapKey:   e.Str("PQ_BOOTSTRAP_KEY", ""),
		PQIdentityDir:    e.Str("PQ_IDENTITY_DIR", ""),
		PQKexOnly:        e.Bool("PQ_KEX_ONLY", false),
		PQProofValidity:  e.Dur("PQ_PROOF_VALIDITY", 60*time.Second),
		PQUpgradeTimeout: e.Dur("PQ_UPGRADE_TIMEOUT", 30*time.Second),
		HTTPTimeout:      e.Dur("HTTP_TIMEOUT", 15*time.Second),
	}
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	c.DialOverrides = overrides
	if len(c.TrustBundle) == 0 {
		e.Fail("RIC_TRUST_BUNDLE is required")
	}
	if err := c.Validate(); err != nil {
		e.Fail("%v", err)
	}
	return c, e.Err()
}

// Validate checks method-independent invariants.
func (c Config) Validate() error {
	switch c.Method {
	case MethodLongTerm, MethodEphemeral, MethodDPoP:
	default:
		return fmt.Errorf("XAPP_METHOD must be A, B or C, got %q", c.Method)
	}
	switch c.Rotation {
	case RotateOnCertExpiry, RotateEveryToken:
	default:
		return fmt.Errorf("ROTATION_POLICY must be %q or %q", RotateOnCertExpiry, RotateEveryToken)
	}
	if c.CertLifetime <= 0 {
		return fmt.Errorf("CERT_LIFETIME must be positive")
	}
	if c.RenewBefore >= c.CertLifetime {
		return fmt.Errorf("RENEW_BEFORE (%s) must be shorter than CERT_LIFETIME (%s)", c.RenewBefore, c.CertLifetime)
	}
	if c.PQEnabled {
		switch c.PQIssuer {
		case PQIssuerShim:
			if c.PQShimURL == "" {
				return fmt.Errorf("PQ_SHIM_URL is required when PQ_ISSUER is %q", PQIssuerShim)
			}
		case PQIssuerKeycloak:
		default:
			return fmt.Errorf("PQ_ISSUER must be %q or %q, got %q", PQIssuerShim, PQIssuerKeycloak, c.PQIssuer)
		}
		if !strings.HasPrefix(c.PQKeyAlg, "ML-DSA-") {
			return fmt.Errorf("PQ_IDENTITY_KEY_ALG must be an ML-DSA parameter set, got %q", c.PQKeyAlg)
		}
		if c.Method == MethodDPoP && !strings.HasPrefix(c.PQDPoPAlg, "ML-DSA-") {
			return fmt.Errorf("PQ_DPOP_ALG must be an ML-DSA parameter set, got %q", c.PQDPoPAlg)
		}
	}
	return nil
}

func (c Config) renewBefore() time.Duration { return c.renewBeforeFor(c.CertLifetime) }

// renewBeforeFor is the renewal margin for a given certificate lifetime.
func (c Config) renewBeforeFor(lifetime time.Duration) time.Duration {
	if c.RenewBefore > 0 {
		return c.RenewBefore
	}
	return lifetime / 5
}

// pqCertLifetime is the lifetime requested for the post-quantum certificate; it
// defaults to the classical one so Method B rotates both on the same schedule.
func (c Config) pqCertLifetime() time.Duration {
	if c.PQCertLifetime > 0 {
		return c.PQCertLifetime
	}
	return c.CertLifetime
}

// upgradeURL is the shim endpoint that exchanges a classical token for a PQ one.
func (c Config) upgradeURL() string {
	return strings.TrimRight(c.PQShimURL, "/") + "/v1/upgrade"
}
EOF
```


## 5A.3 Identity and enrollment

The check at the end of `Enroll` is worth noting: the client verifies the CA returned a
certificate **for the key it actually holds**. Fail-closed at both ends, not only at the
server.

```bash
cat > ~/pqc-xapp-auth/xapp-client/identity.go <<'EOF'
package xappclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// Identity holds the xApp's current RIC-CA certificate. TLS configurations read it on
// every handshake (GetClientCertificate / GetCertificate), so a rotation takes effect
// on the next connection without rebuilding clients or servers.
type Identity struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// Current returns the active credential or nil.
func (i *Identity) Current() *tls.Certificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cert
}

// Leaf returns the active certificate or nil.
func (i *Identity) Leaf() *x509.Certificate {
	if c := i.Current(); c != nil {
		return c.Leaf
	}
	return nil
}

func (i *Identity) set(c *tls.Certificate) {
	i.mu.Lock()
	i.cert = c
	i.mu.Unlock()
}

// RotationStats describes one certificate enrollment/renewal, for measurement.
type RotationStats struct {
	KeyGen    time.Duration
	RoundTrip time.Duration // CSR build + HTTPS round trip to the RIC CA + response parsing
	Total     time.Duration
	Serial    string
	NotAfter  time.Time
	KeyAlg    string // EC-P256, ML-DSA-65, ...
	CertBytes int    // DER size of the issued certificate
	Plane     string // classical or post-quantum
}

// Enroller calls the RIC CA enrollment service.
type Enroller struct {
	BaseURL   string
	Roots     *x509.CertPool
	Overrides map[string]string
	Timeout   time.Duration
	// PQKexOnly requires the ML-KEM hybrid group for the CA connection.
	PQKexOnly bool
}

// Enroll sends a CSR for key, authenticated by auth. renew selects /v1/renew
// (operational credential) instead of /v1/enroll (bootstrap credential).
func (e *Enroller) Enroll(ctx context.Context, auth *tls.Certificate, key crypto.Signer, dnsNames []string, lifetime time.Duration, renew bool) (*tls.Certificate, error) {
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: auth.Leaf.Subject.CommonName},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("build CSR: %w", err)
	}
	path := "/v1/enroll"
	if renew {
		path = "/v1/renew"
	}
	u := e.BaseURL + path + "?lifetime=" + url.QueryEscape(lifetime.String())

	// A dedicated, non-pooled transport: the authenticating certificate differs per call.
	tr := netx.NewTransport(&tls.Config{
		MinVersion:       tls.VersionTLS13,
		RootCAs:          e.Roots,
		Certificates:     []tls.Certificate{*auth},
		CurvePreferences: netx.CurvePreferences(e.PQKexOnly),
	}, e.Overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: e.Timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u,
		bytes.NewReader(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("RIC CA %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIC CA %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(body))
	}
	certs, err := pki.ParseCertsPEM(body)
	if err != nil {
		return nil, fmt.Errorf("RIC CA response: %w", err)
	}
	leafKey, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !leafKey.Equal(key.Public()) {
		return nil, errors.New("RIC CA returned a certificate for a different key")
	}
	out := &tls.Certificate{PrivateKey: key, Leaf: certs[0]}
	for _, c := range certs {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out, nil
}

func loadCredential(certPath, keyPath string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if c.Leaf == nil {
		if c.Leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func persistCredential(dir string, c *tls.Certificate) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(c.PrivateKey)
	if err != nil {
		return err
	}
	// write key first, then certificate, each via rename for atomicity
	if err := writeAtomic(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "tls.crt"), chain, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
EOF
```


## 5A.4 Token issuance

```bash
cat > ~/pqc-xapp-auth/xapp-client/issuer.go <<'EOF'
package xappclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TokenRequest carries everything needed for one issuance call.
type TokenRequest struct {
	TokenURL   string
	ClientID   string
	Scope      string
	DPoPProof  string       // set for method C
	HTTPClient *http.Client // mTLS client presenting the xApp identity
}

// TokenResponse is the authorization server's answer.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	ReceivedAt  time.Time
}

// Issuer is the single token-issuance path used by every method. A later phase can
// insert a re-signing shim (e.g. ML-DSA) by wrapping it with Client.SetIssuer,
// without touching any call site.
type Issuer interface {
	Issue(ctx context.Context, req TokenRequest) (*TokenResponse, error)
}

// IssuerError is a non-200 token endpoint response.
type IssuerError struct {
	Status    int
	Body      string
	DPoPNonce string
}

func (e *IssuerError) Error() string {
	return fmt.Sprintf("token endpoint HTTP %d: %s", e.Status, e.Body)
}

// NeedsNonce reports whether the server demanded a DPoP nonce (RFC 9449 §8).
func (e *IssuerError) NeedsNonce() bool {
	return e.DPoPNonce != "" && strings.Contains(e.Body, "use_dpop_nonce")
}

// KeycloakIssuer performs the OAuth 2.0 client_credentials grant against Keycloak.
type KeycloakIssuer struct{}

// Issue implements Issuer.
func (KeycloakIssuer) Issue(ctx context.Context, r TokenRequest) (*TokenResponse, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {r.ClientID}}
	if r.Scope != "" {
		form.Set("scope", r.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if r.DPoPProof != "" {
		req.Header.Set("DPoP", r.DPoPProof)
	}
	resp, err := r.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &IssuerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body)), DPoPNonce: resp.Header.Get("DPoP-Nonce")}
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response has no access_token")
	}
	tr.ReceivedAt = time.Now()
	return &tr, nil
}
EOF
```


## 5A.5 Check

```bash
cd ~/pqc-xapp-auth && for f in internal/pqbind/pqbind.go:9 xapp-client/config.go:228 xapp-client/identity.go:178 xapp-client/issuer.go:94; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `internal/pqbind/pqbind.go` | 9 |
| `xapp-client/config.go` | 228 |
| `xapp-client/identity.go` | 178 |
| `xapp-client/issuer.go` | 94 |


All four must match exactly. If one is short, delete it and re-paste that block.

Next: `chunk-05b-client-core.md`.
