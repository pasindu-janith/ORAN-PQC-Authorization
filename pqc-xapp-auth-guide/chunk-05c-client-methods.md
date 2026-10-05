# Chunk 5C - Client library: the three methods

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** Methods A, B and C, the post-quantum upgrade path, and the first successful
build of the client library.

**Needs the cluster?** No.

---

## Three things to notice

- **`certbound.go` is both Method A and Method B.** The only difference is
  `base.rotateKeys` and the certificate lifetime. One file, two methods.
- **`BuildDPoPProof` is the single proof builder.** The *signer* decides the algorithm,
  so ES256 and ML-DSA-44 proofs come out of identical code - the same pattern as the CA
  `branchFor`.
- **`upgradeToPQ` demands proof of possession of *both* credentials in one request.**
  Classical via mTLS plus the token; post-quantum via the `X-PQ-Proof` header. If it
  accepted either alone, anyone holding one credential could move the binding to the
  other.

## 5C.1 Methods A and B

```bash
cat > ~/pqc-xapp-auth/xapp-client/certbound.go <<'EOF'
package xappclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// certBound implements Methods A and B (RFC 8705). The only differences between the
// two are the certificate lifetime and base.rotateKeys; the Keycloak configuration
// and this code path are shared.
//
// In post-quantum mode the same flow runs twice over: Keycloak issues a token bound
// to the classical certificate, then the shim re-issues it, ML-DSA-signed and bound
// to the ML-DSA certificate, which is the one presented to resource servers.
type certBound struct {
	*base
}

// Token returns a token bound to the current certificate. Rotation is driven by the
// certificate lifetime, not the token lifetime: when a certificate enters its renewal
// window a new key/certificate is obtained first, which invalidates the cached token.
func (c *certBound) Token(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	if t := c.cached; t != nil && t.usable(time.Now()) {
		return t, nil
	}
	if c.rotateKeys && c.cfg.Rotation == RotateEveryToken && c.tokensOnCert > 0 {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *certBound) IssueToken(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *certBound) issueLocked(ctx context.Context) (*Token, error) {
	// The certificate the authorization server authenticates and binds to: the
	// classical one while the shim is in the path, the ML-DSA one once it is not.
	leaf := c.asIdentity().Leaf()
	if leaf == nil {
		return nil, fmt.Errorf("client not started: no identity certificate")
	}
	resp, err := c.getIssuer().Issue(ctx, TokenRequest{
		TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, HTTPClient: c.asClient(),
	})
	if err != nil {
		return nil, c.asLegError(err)
	}
	tok, err := newToken(resp)
	if err != nil {
		return nil, err
	}
	// Keycloak issues a token even if the certificate never reached it, so the binding
	// is checked on receipt and its absence is an error.
	x5t, err := cnfMember(tok.Claims, "x5t#S256")
	if err != nil {
		c.log.Error("token_binding_missing", "error", err,
			"hint", "client certificate did not reach Keycloak or 'OAuth 2.0 Mutual TLS Certificate Bound Access Tokens' is off")
		return nil, err
	}
	if want := pki.ThumbprintS256(leaf); x5t != want {
		return nil, fmt.Errorf("%w: cnf.x5t#S256=%s, presented certificate=%s", ErrBindingMismatch, x5t, want)
	}
	tok.Binding, tok.Thumbprint, tok.CertNotAfter = "x5t#S256", x5t, leaf.NotAfter
	c.log.Debug("token_issued", "binding", tok.Binding, "cnf", x5t, "alg", tok.Alg,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339), "bytes", len(tok.Value))

	switch {
	case c.pqDirect():
		// The authorization server already issued the post-quantum token, bound to
		// the ML-DSA certificate verified above. Nothing to upgrade.
		if err := c.requirePQToken(tok); err != nil {
			return nil, err
		}
	case c.cfg.PQEnabled:
		if tok, err = c.upgradeCertBound(ctx, tok); err != nil {
			return nil, err
		}
	}
	c.cached = tok
	c.tokensOnCert++
	return tok, nil
}

// upgradeCertBound transfers the binding from the classical certificate to the
// post-quantum one and returns the ML-DSA-signed token.
func (c *certBound) upgradeCertBound(ctx context.Context, classical *Token) (*Token, error) {
	pqLeaf := c.pqID.Leaf()
	if pqLeaf == nil {
		return nil, fmt.Errorf("post-quantum identity certificate is not available")
	}
	tok, err := c.upgradeToPQ(ctx, classical, bearerDecorator, c.pqCertProof)
	if err != nil {
		return nil, err
	}
	if err := c.verifyPQBinding(tok, "x5t#S256", pki.ThumbprintS256(pqLeaf)); err != nil {
		return nil, err
	}
	tok.CertNotAfter = pqLeaf.NotAfter
	c.log.Debug("pq_token_ready", "alg", tok.Alg, "cnf", tok.Thumbprint,
		"cert_key_alg", pki.KeyAlgName(pqLeaf.PublicKey), "bytes", len(tok.Value))
	return tok, nil
}

func bearerDecorator(req *http.Request, classical *Token) error {
	req.Header.Set("Authorization", "Bearer "+classical.Value)
	return nil
}

func (c *certBound) Authorize(req *http.Request, tok *Token) error {
	req.Header.Set("Authorization", "Bearer "+tok.Value)
	return nil
}

func (c *certBound) Do(req *http.Request) (*http.Response, error) {
	tok, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	if err := c.Authorize(req, tok); err != nil {
		return nil, err
	}
	return c.HTTPClient().Do(req)
}
EOF
```


## 5C.2 Method C

```bash
cat > ~/pqc-xapp-auth/xapp-client/dpop.go <<'EOF'
package xappclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
)

// dpopClient implements Method C (RFC 9449). The transport uses the xApp RIC
// certificate (every connection is mTLS and Keycloak authenticates the client with
// it), while the access token is bound to the DPoP key via cnf.jkt.
//
// In post-quantum mode the client holds two DPoP keys: the classical one, which
// Keycloak can verify, and an ML-DSA one, which the shim binds into the upgraded
// token and which signs every proof sent to resource servers.
type dpopClient struct {
	*base
	signer jose.Signer
	jkt    string

	pqSigner jose.Signer // ML-DSA proof key (PQ mode)
	pqJKT    string

	nonceMu sync.Mutex
	nonces  map[string]string // DPoP-Nonce per origin
}

// DPoP exposes the proof keys to tests and benchmarks.
type DPoP interface {
	Signer() jose.Signer
	JKT() string
	Proof(method, rawURL, accessToken string) (string, error)
	// PQSigner is the ML-DSA proof key, nil outside PQ mode.
	PQSigner() jose.Signer
	PQJKT() string
}

func (c *dpopClient) Signer() jose.Signer   { return c.signer }
func (c *dpopClient) JKT() string           { return c.jkt }
func (c *dpopClient) PQSigner() jose.Signer { return c.pqSigner }
func (c *dpopClient) PQJKT() string         { return c.pqJKT }

// BuildDPoPProof creates a DPoP proof JWT (RFC 9449 section 4.2). When accessToken is
// not empty the proof carries ath = base64url(SHA-256(accessToken)). The signer
// decides the algorithm, so the same function produces ES256 and ML-DSA-44 proofs.
func BuildDPoPProof(s jose.Signer, method, rawURL, accessToken, nonce string, now time.Time) (string, error) {
	htu, err := netx.NormalizeHTU(rawURL)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := map[string]any{"jti": jose.B64(jti), "htm": method, "htu": htu, "iat": now.Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = jose.B64(sum[:])
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.SignCompact(map[string]any{"typ": "dpop+jwt", "jwk": s.PublicKey()}, claims)
}

func origin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func (c *dpopClient) nonce(rawURL string) string {
	c.nonceMu.Lock()
	defer c.nonceMu.Unlock()
	return c.nonces[origin(rawURL)]
}

func (c *dpopClient) setNonce(rawURL, n string) {
	c.nonceMu.Lock()
	c.nonces[origin(rawURL)] = n
	c.nonceMu.Unlock()
}

// asSigner is the proof key the authorization server binds the token to, with its
// thumbprint. It is the ML-DSA key only when the server issues post-quantum tokens
// itself; otherwise the shim transfers the binding afterwards.
func (c *dpopClient) asSigner() (jose.Signer, string) {
	if c.pqDirect() && c.pqSigner != nil {
		return c.pqSigner, c.pqJKT
	}
	return c.signer, c.jkt
}

// Proof builds a proof with the classical key (used with Keycloak and the shim).
func (c *dpopClient) Proof(method, rawURL, accessToken string) (string, error) {
	return BuildDPoPProof(c.signer, method, rawURL, accessToken, c.nonce(rawURL), time.Now())
}

// proofFor picks the key that matches the token: ML-DSA for an upgraded token,
// classical otherwise.
func (c *dpopClient) proofFor(tok *Token, method, rawURL string) (string, error) {
	signer := c.signer
	if tok.PostQuantum {
		if c.pqSigner == nil {
			return "", errors.New("post-quantum token but no ML-DSA proof key")
		}
		signer = c.pqSigner
	}
	return BuildDPoPProof(signer, method, rawURL, tok.Value, c.nonce(rawURL), time.Now())
}

func (c *dpopClient) Token(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	if t := c.cached; t != nil && t.usable(time.Now()) {
		return t, nil
	}
	return c.issueLocked(ctx)
}

func (c *dpopClient) IssueToken(ctx context.Context) (*Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.needsRenewal() {
		if _, err := c.rotateLocked(ctx); err != nil {
			return nil, err
		}
	}
	return c.issueLocked(ctx)
}

func (c *dpopClient) issueLocked(ctx context.Context) (*Token, error) {
	// The proof key the authorization server binds the token to: the classical one
	// while the shim is in the path, the ML-DSA one once the server can verify it.
	signer, wantJKT := c.asSigner()
	var resp *TokenResponse
	for attempt := 0; ; attempt++ {
		proof, err := BuildDPoPProof(signer, http.MethodPost, c.cfg.TokenURL, "", c.nonce(c.cfg.TokenURL), time.Now())
		if err != nil {
			return nil, err
		}
		resp, err = c.getIssuer().Issue(ctx, TokenRequest{
			TokenURL: c.cfg.TokenURL, ClientID: c.cfg.ClientID, Scope: c.cfg.Scope, DPoPProof: proof, HTTPClient: c.asClient(),
		})
		var ie *IssuerError
		if err != nil && attempt == 0 && errors.As(err, &ie) && ie.NeedsNonce() {
			c.setNonce(c.cfg.TokenURL, ie.DPoPNonce)
			continue
		}
		if err != nil {
			return nil, c.asLegError(err)
		}
		break
	}
	tok, err := newToken(resp)
	if err != nil {
		return nil, err
	}
	jkt, err := cnfMember(tok.Claims, "jkt")
	if err != nil {
		c.log.Error("token_binding_missing", "error", err, "hint", "'Require DPoP bound tokens' is off or the DPoP header was dropped")
		return nil, err
	}
	if jkt != wantJKT {
		return nil, fmt.Errorf("%w: cnf.jkt=%s, proof key=%s", ErrBindingMismatch, jkt, wantJKT)
	}
	if !strings.EqualFold(resp.TokenType, "DPoP") {
		return nil, fmt.Errorf("%w: token_type is %q, expected DPoP", ErrBindingMismatch, resp.TokenType)
	}
	tok.Binding, tok.Thumbprint = "jkt", jkt
	c.log.Debug("token_issued", "binding", tok.Binding, "cnf", jkt, "alg", tok.Alg,
		"expires_at", tok.ExpiresAt.UTC().Format(time.RFC3339), "bytes", len(tok.Value))

	switch {
	case c.pqDirect():
		// Already bound to the ML-DSA proof key verified above; no upgrade needed.
		if err := c.requirePQToken(tok); err != nil {
			return nil, err
		}
	case c.cfg.PQEnabled:
		if tok, err = c.upgradeDPoP(ctx, tok); err != nil {
			return nil, err
		}
	}
	c.cached = tok
	return tok, nil
}

// upgradeDPoP transfers the binding from the classical DPoP key to the ML-DSA one.
// The upgrade request proves possession of the classical key with an ordinary DPoP
// proof, and of the ML-DSA key with the post-quantum binding proof.
func (c *dpopClient) upgradeDPoP(ctx context.Context, classical *Token) (*Token, error) {
	decorate := func(req *http.Request, tok *Token) error {
		proof, err := c.Proof(req.Method, req.URL.String(), tok.Value)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "DPoP "+tok.Value)
		req.Header.Set("DPoP", proof)
		return nil
	}
	tok, err := c.upgradeToPQ(ctx, classical, decorate, c.pqJWKProof)
	if err != nil {
		return nil, err
	}
	if err := c.verifyPQBinding(tok, "jkt", c.pqJKT); err != nil {
		return nil, err
	}
	c.log.Debug("pq_token_ready", "alg", tok.Alg, "cnf", tok.Thumbprint,
		"proof_alg", c.pqSigner.Alg(), "bytes", len(tok.Value))
	return tok, nil
}

// Authorize sets the DPoP scheme and a fresh proof bound to this request and token.
func (c *dpopClient) Authorize(req *http.Request, tok *Token) error {
	proof, err := c.proofFor(tok, req.Method, req.URL.String())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+tok.Value)
	req.Header.Set("DPoP", proof)
	return nil
}

func (c *dpopClient) Do(req *http.Request) (*http.Response, error) {
	tok, err := c.Token(req.Context())
	if err != nil {
		return nil, err
	}
	if err := c.Authorize(req, tok); err != nil {
		return nil, err
	}
	client := c.HTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	// Resource-server nonce challenge (RFC 9449 section 9): retry once if the body can be replayed.
	if n := resp.Header.Get("DPoP-Nonce"); resp.StatusCode == http.StatusUnauthorized && n != "" &&
		strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") && (req.Body == nil || req.GetBody != nil) {
		resp.Body.Close()
		c.setNonce(req.URL.String(), n)
		retry := req.Clone(req.Context())
		if req.GetBody != nil {
			if retry.Body, err = req.GetBody(); err != nil {
				return nil, err
			}
		}
		if err := c.Authorize(retry, tok); err != nil {
			return nil, err
		}
		return client.Do(retry)
	}
	return resp, nil
}
EOF
```


## 5C.3 The post-quantum upgrade path

```bash
cat > ~/pqc-xapp-auth/xapp-client/pq.go <<'EOF'
package xappclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v4/cert"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pqbind"
)

// upgradeResponse mirrors pqshim.UpgradeResponse.
type upgradeResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	Alg         string         `json:"alg"`
	Cnf         map[string]any `json:"cnf"`
}

// decorator sets the Authorization header (and, for method C, the classical DPoP
// proof) on the upgrade request.
type decorator func(req *http.Request, classical *Token) error

// pqProofFunc builds the ML-DSA proof that carries the new binding.
type pqProofFunc func(htu, classicalToken string) (string, error)

// upgradeToPQ exchanges a classical Keycloak token for an ML-DSA-signed token bound
// to this client's post-quantum credential. The request travels over the classical
// mTLS identity, because the shim first re-checks the classical binding exactly as a
// resource server would.
func (b *base) upgradeToPQ(ctx context.Context, classical *Token, decorate decorator, proof pqProofFunc) (*Token, error) {
	url := b.cfg.upgradeURL()
	ctx, cancel := context.WithTimeout(ctx, b.cfg.PQUpgradeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	if err := decorate(req, classical); err != nil {
		return nil, err
	}
	pqProof, err := proof(url, classical.Value)
	if err != nil {
		return nil, fmt.Errorf("build post-quantum binding proof: %w", err)
	}
	req.Header.Set(pqbind.ProofHeader, pqProof)

	start := time.Now()
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pq-shim upgrade: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pq-shim upgrade: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var up upgradeResponse
	if err := json.Unmarshal(body, &up); err != nil {
		return nil, fmt.Errorf("pq-shim response: %w", err)
	}
	tok, err := newToken(&TokenResponse{AccessToken: up.AccessToken, TokenType: up.TokenType,
		ExpiresIn: up.ExpiresIn, ReceivedAt: time.Now()})
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(tok.Alg, "ML-DSA-") {
		return nil, fmt.Errorf("%w: upgraded token is signed with %q, not ML-DSA", ErrBindingMismatch, tok.Alg)
	}
	tok.PostQuantum = true
	tok.Classical = classical
	b.log.Debug("token_upgraded", "alg", tok.Alg, "bytes", len(tok.Value),
		"classical_bytes", len(classical.Value), "elapsed_ms", ms(time.Since(start)))
	return tok, nil
}

// pqCertProof proves possession of the post-quantum identity certificate (Methods A
// and B). The certificate chain travels in the x5c protected header, so the shim can
// verify it against the post-quantum CA and bind the new token to its thumbprint.
func (b *base) pqCertProof(htu, classicalToken string) (string, error) {
	current := b.pqID.Current()
	if current == nil {
		return "", fmt.Errorf("no post-quantum identity certificate")
	}
	alg := pki.KeyAlgName(current.Leaf.PublicKey)
	signer, err := jose.SignerFromKey(alg, current.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("post-quantum signer (%s): %w", alg, err)
	}
	chain := &cert.Chain{}
	for _, der := range current.Certificate {
		if err := chain.AddString(base64.StdEncoding.EncodeToString(der)); err != nil {
			return "", err
		}
	}
	return signer.SignCompact(
		map[string]any{"typ": pqbind.ProofType, "x5c": chain},
		pqProofClaims(htu, classicalToken))
}

// pqJWKProof proves possession of the post-quantum DPoP key (Method C). The AKP
// public key travels in the jwk header and becomes the new cnf.jkt.
func (c *dpopClient) pqJWKProof(htu, classicalToken string) (string, error) {
	if c.pqSigner == nil {
		return "", fmt.Errorf("no post-quantum DPoP key")
	}
	return c.pqSigner.SignCompact(
		map[string]any{"typ": pqbind.ProofType, "jwk": c.pqSigner.PublicKey()},
		pqProofClaims(htu, classicalToken))
}

func pqProofClaims(htu, classicalToken string) map[string]any {
	jti := make([]byte, 18)
	_, _ = rand.Read(jti)
	sum := sha256.Sum256([]byte(classicalToken))
	normalised, err := netx.NormalizeHTU(htu)
	if err != nil {
		normalised = htu
	}
	return map[string]any{
		"jti": jose.B64(jti),
		"htm": http.MethodPost,
		"htu": normalised,
		"iat": time.Now().Unix(),
		"ath": jose.B64(sum[:]),
	}
}

// verifyPQBinding checks that the shim bound the upgraded token to the credential we
// actually hold, which is the same fail-closed check the client applies to Keycloak.
func (b *base) verifyPQBinding(tok *Token, member, want string) error {
	got, err := cnfMember(tok.Claims, member)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%w: upgraded token cnf.%s=%s, post-quantum credential=%s", ErrBindingMismatch, member, got, want)
	}
	tok.Binding, tok.Thumbprint = member, got
	return nil
}
EOF
```


## 5C.4 A configuration test

```bash
cat > ~/pqc-xapp-auth/xapp-client/config_test.go <<'EOF'
package xappclient

import "testing"

// The PQ_ISSUER switch decides whether the shim is in the path. Getting it wrong must
// be a configuration error, never a silent downgrade to a classical token.
func TestPQIssuerValidation(t *testing.T) {
	base := Config{Method: MethodLongTerm, Rotation: RotateOnCertExpiry, CertLifetime: DefaultLifetime(MethodLongTerm)}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"shim issuer needs the shim URL", func(c *Config) {
			c.PQEnabled, c.PQIssuer = true, PQIssuerShim
		}, true},
		{"shim issuer with the shim URL is accepted", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQShimURL = true, PQIssuerShim, "https://pq-shim.ricsec.svc.cluster.local:8443"
			c.PQKeyAlg = "ML-DSA-65"
		}, false},
		{"keycloak issuer needs no shim URL", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQKeyAlg = true, PQIssuerKeycloak, "ML-DSA-65"
		}, false},
		{"an unknown issuer is refused", func(c *Config) {
			c.PQEnabled, c.PQIssuer, c.PQKeyAlg = true, "duende", "ML-DSA-65"
		}, true},
		{"the issuer is irrelevant outside post-quantum mode", func(c *Config) {
			c.PQIssuer = ""
		}, false},
	}
	for _, tc := range cases {
		c := base
		tc.mutate(&c)
		err := c.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}
EOF
```


## 5C.5 Build and test - the first full build since Chunk 2

```bash
cd ~/pqc-xapp-auth && for f in xapp-client/certbound.go:144 xapp-client/dpop.go:272 xapp-client/pq.go:155 xapp-client/config_test.go:43; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `xapp-client/certbound.go` | 144 |
| `xapp-client/dpop.go` | 272 |
| `xapp-client/pq.go` | 155 |
| `xapp-client/config_test.go` | 43 |


```bash
cd ~/pqc-xapp-auth && go mod tidy && go build -p=2 ./... && go vet ./xapp-client/
```

```bash
cd ~/pqc-xapp-auth && go test -p=2 ./internal/... ./xapp-client/
```

`go mod tidy` pulls `github.com/lestrrat-go/jwx/v4/cert`, used by `pqCertProof` for the
`x5c` header. It is part of the same `jwx` module, so no new dependency appears.

---

**State after this chunk:** the PKI, the CA service, Keycloak and the client library are
all built, with Milestones 1 and 2 passing. What is missing is the enforcement point -
nothing yet *checks* a binding. That is Chunk 6.

Next: Chunk 6, the resource-side validator.
