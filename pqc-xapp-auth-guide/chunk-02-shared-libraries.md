# Chunk 2 — The shared libraries

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** the JOSE, networking, configuration and logging code every later component
links against.

**Needs the cluster?** No.

---

## Why these matter

This is where the security *policy* lives, as opposed to the cryptography. Three
decisions to be able to point at:

- **`LookupAlg` refuses `alg: none` and every `HS*` algorithm.** The classic JWT attack
  is to re-sign a token with `none`, or with HMAC using the server's public key as the
  secret. Because every verification in the project goes through this one function,
  that attack is not defended against — it is **unreachable**.
- **`JWK.PublicKey()` refuses any key carrying private members** (`d`, `p`, `q`, `k`,
  and `priv` for ML-DSA). A DPoP proof carries its own public key in the header; this
  stops a peer smuggling a private key in.
- **ML-DSA keys serialise as `kty: "AKP"` with a `pub` member** — that is RFC 9964, and
  the reason `jwx v4` is the single dependency.

## 2.1 The JOSE package

```bash
cat > ~/pqc-xapp-auth/internal/jose/jose.go <<'EOF'
// Package jose is a thin adapter over github.com/lestrrat-go/jwx/v4.
//
// The library performs all JOSE work: JWS signing and verification, JWK parsing
// and serialisation, and RFC 7638 thumbprints. Because jwx v4 on Go 1.27
// implements ML-DSA natively (RFC 9964: alg ML-DSA-44/65/87, kty "AKP" with the
// thumbprint taken over alg, kty and pub), classical and post-quantum algorithms
// are handled by exactly the same code paths here and in the validator.
//
// What this package adds on top of the library is policy, not cryptography:
//   - "none" and symmetric (HS*) algorithms are never accepted,
//   - a JWK carrying private members is never usable as a verification key.
package jose

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

var b64 = base64.RawURLEncoding

// B64 encodes bytes as unpadded base64url.
func B64(b []byte) string { return b64.EncodeToString(b) }

// ErrAlgNotAllowed is returned for "none" and symmetric algorithms.
var ErrAlgNotAllowed = errors.New("algorithm not allowed")

// LookupAlg maps a JWS "alg" header to a jwx signature algorithm, refusing
// algorithms that must never be used to verify a sender-constrained token.
func LookupAlg(alg string) (jwa.SignatureAlgorithm, error) {
	if alg == "" {
		return jwa.SignatureAlgorithm{}, errors.New("JWS header has no alg")
	}
	if strings.EqualFold(alg, "none") || strings.HasPrefix(strings.ToUpper(alg), "HS") {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w: %s", ErrAlgNotAllowed, alg)
	}
	sa, ok := jwa.LookupSignatureAlgorithm(alg)
	if !ok {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported JWS alg %q", alg)
	}
	return sa, nil
}

// asKey accepts a jwk.Key, or any raw key the library can import.
func asKey(key any) (jwk.Key, error) {
	if k, ok := key.(jwk.Key); ok {
		return k, nil
	}
	return jwk.Import[jwk.Key](key)
}

// JWK is a JSON Web Key kept as a generic object, which is how DPoP proofs carry
// the proof key in their header. Conversion and thumbprinting are delegated to jwx.
type JWK map[string]any

// Str returns a string member or "".
func (k JWK) Str(name string) string {
	s, _ := k[name].(string)
	return s
}

// privateMembers must never appear in a key received from a peer. "priv" is the
// ML-DSA (AKP) private member from RFC 9964; the others are the classical ones.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "priv"}

func (k JWK) parse() (jwk.Key, error) {
	raw, err := json.Marshal(map[string]any(k))
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(raw)
}

// PublicKey converts the JWK into a verification key. Keys carrying private
// material are refused outright.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	for _, m := range privateMembers {
		if _, has := k[m]; has {
			return nil, fmt.Errorf("jwk contains private member %q", m)
		}
	}
	key, err := k.parse()
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint (base64url), the value
// carried in cnf.jkt. For AKP keys jwx applies the RFC 9964 member set (alg, kty, pub).
func (k JWK) Thumbprint() (string, error) {
	key, err := k.parse()
	if err != nil {
		return "", err
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return B64(tp), nil
}

// JWKFromKey renders any key (raw or jwk.Key) as a public JWK object.
func JWKFromKey(key any) (JWK, error) {
	k, err := asKey(key)
	if err != nil {
		return nil, err
	}
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		return nil, err
	}
	var out JWK
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
EOF
```


```bash
cat > ~/pqc-xapp-auth/internal/jose/jws.go <<'EOF'
package jose

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jws"
)

// JWS is a compact JWS whose header and payload have been decoded for inspection
// but whose signature has NOT been checked yet. Verification is done by jwx in
// VerifySignature, which re-verifies the original compact serialisation.
type JWS struct {
	Compact string
	Header  map[string]any
	Payload []byte
}

// ParseCompact splits and decodes a compact JWS. It performs no verification.
func ParseCompact(token string) (*JWS, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("compact JWS must have 3 parts, got %d", len(parts))
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header is not base64url: %w", err)
	}
	header, err := decodeObject(hb)
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	if _, err := b64.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("signature is not base64url: %w", err)
	}
	return &JWS{Compact: token, Header: header, Payload: payload}, nil
}

func decodeObject(b []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("not a JSON object")
	}
	return m, nil
}

func (j *JWS) headerString(name string) string {
	s, _ := j.Header[name].(string)
	return s
}

// Alg returns the "alg" header.
func (j *JWS) Alg() string { return j.headerString("alg") }

// Kid returns the "kid" header.
func (j *JWS) Kid() string { return j.headerString("kid") }

// Typ returns the "typ" header.
func (j *JWS) Typ() string { return j.headerString("typ") }

// Claims decodes the payload as a JSON object (numbers kept as json.Number).
func (j *JWS) Claims() (map[string]any, error) { return decodeObject(j.Payload) }

// VerifySignature verifies the signature with key, dispatching on the "alg"
// header through jwx. The same call handles ES256 and ML-DSA-65 alike.
func (j *JWS) VerifySignature(key any) error {
	alg, err := LookupAlg(j.Alg())
	if err != nil {
		return err
	}
	k, err := asKey(key)
	if err != nil {
		return fmt.Errorf("verification key unusable: %w", err)
	}
	if _, err := jws.Verify([]byte(j.Compact), jws.WithKey(alg, k)); err != nil {
		return err
	}
	return nil
}
EOF
```


```bash
cat > ~/pqc-xapp-auth/internal/jose/signer.go <<'EOF'
package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Signer produces compact JWS objects (DPoP proofs, shim-issued tokens). The whole
// JWS is produced by jwx; this project never assembles signing input or signature
// bytes itself.
type Signer interface {
	// Alg is the JWS "alg" value, e.g. ES256 or ML-DSA-65.
	Alg() string
	// PublicJWK is the public key as a JWK object (AKP for ML-DSA).
	PublicJWK() JWK
	// Key exposes the underlying private jwx key.
	Key() jwk.Key
	// PublicKey is the public jwx key, used as the DPoP "jwk" protected header.
	PublicKey() jwk.Key
	// SignCompact signs claims with the given protected headers.
	SignCompact(header map[string]any, claims any) (string, error)
}

type jwxSigner struct {
	alg    jwa.SignatureAlgorithm
	key    jwk.Key
	pubKey jwk.Key
	pub    JWK
}

// GenerateSigner creates a fresh key pair for alg and returns a Signer.
// Supported: ES256/384/512 (classical) and ML-DSA-44/65/87 (FIPS 204, RFC 9964).
func GenerateSigner(alg string) (Signer, error) {
	var raw any
	var err error
	switch alg {
	case "ES256":
		raw, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ES384":
		raw, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ES512":
		raw, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "ML-DSA-44":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA44())
	case "ML-DSA-65":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA65())
	case "ML-DSA-87":
		raw, err = mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, fmt.Errorf("unsupported signing alg %q", alg)
	}
	if err != nil {
		return nil, err
	}
	return SignerFromKey(alg, raw)
}

// SignerFromKey wraps an existing private key.
func SignerFromKey(alg string, raw any) (Signer, error) {
	sa, err := LookupAlg(alg)
	if err != nil {
		return nil, err
	}
	key, err := asKey(raw)
	if err != nil {
		return nil, err
	}
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	pub, err := JWKFromKey(key)
	if err != nil {
		return nil, err
	}
	return &jwxSigner{alg: sa, key: key, pubKey: pubKey, pub: pub}, nil
}

func (s *jwxSigner) Alg() string    { return s.alg.String() }
func (s *jwxSigner) PublicJWK() JWK { return s.pub }
func (s *jwxSigner) Key() jwk.Key   { return s.key }

// PublicKey returns the public key as a jwx key.
func (s *jwxSigner) PublicKey() jwk.Key { return s.pubKey }

func (s *jwxSigner) SignCompact(header map[string]any, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	hdrs := jws.NewHeaders()
	for k, v := range header {
		if err := hdrs.Set(k, v); err != nil {
			return "", fmt.Errorf("protected header %q: %w", k, err)
		}
	}
	signed, err := jws.Sign(payload, jws.WithKey(s.alg, s.key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
EOF
```


```bash
cat > ~/pqc-xapp-auth/internal/jose/jwks.go <<'EOF'
package jose

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// KeySet caches the verification keys published at a JWKS URL. Keys are never
// embedded: an unknown kid triggers a rate-limited refetch, which also covers
// issuer key rotation and a change of signature algorithm (ES256 to ML-DSA).
// Parsing is done by jwx, so AKP (ML-DSA) keys need no special handling.
type KeySet struct {
	url        string
	client     *http.Client
	ttl        time.Duration
	minRefresh time.Duration

	mu          sync.RWMutex
	set         jwk.Set
	fetched     time.Time
	lastAttempt time.Time
}

// NewKeySet creates a cache for url.
func NewKeySet(url string, client *http.Client, ttl, minRefresh time.Duration) *KeySet {
	return &KeySet{url: url, client: client, ttl: ttl, minRefresh: minRefresh}
}

// Key returns the verification key for kid, checking it is a signing key usable with alg.
func (s *KeySet) Key(ctx context.Context, kid, alg string) (any, error) {
	if kid == "" {
		return nil, fmt.Errorf("JWS header has no kid")
	}
	key, ok := s.lookup(kid)
	if !ok || s.stale() {
		if err := s.refresh(ctx); err != nil && !ok {
			return nil, err
		}
		if key, ok = s.lookup(kid); !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS %s", kid, s.url)
		}
	}
	if use, ok := key.KeyUsage(); ok && use != "" && use != "sig" {
		return nil, fmt.Errorf("kid %q has use %q, not sig", kid, use)
	}
	if ka, ok := key.Algorithm(); ok && ka != nil && ka.String() != "" && ka.String() != alg {
		return nil, fmt.Errorf("kid %q is bound to alg %q but token uses %q", kid, ka.String(), alg)
	}
	return key, nil
}

func (s *KeySet) lookup(kid string) (jwk.Key, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.set == nil {
		return nil, false
	}
	return s.set.LookupKeyID(kid)
}

func (s *KeySet) stale() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.fetched) > s.ttl
}

func (s *KeySet) refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastAttempt.IsZero() && time.Since(s.lastAttempt) < s.minRefresh && time.Since(s.fetched) <= s.ttl {
		return nil
	}
	s.lastAttempt = time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	// ML-DSA public keys are kilobytes, not bytes: keep the limit generous.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}
	s.set = set
	s.fetched = time.Now()
	return nil
}
EOF
```


## 2.2 Networking, configuration, logging

`NormalizeHTU` is the one to remember: DPoP proofs bind to a URL, and client and server
must canonicalise it identically or every request fails. `CurvePreferences(true)` is
what *forces* the ML-KEM hybrid group, so a classical-only peer fails the handshake
rather than silently negotiating a quantum-vulnerable key exchange.

```bash
cat > ~/pqc-xapp-auth/internal/netx/netx.go <<'EOF'
// Package netx provides HTTP transports and the DPoP htu normalisation shared by
// the client and the resource server.
package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ParseDialOverrides parses "host:port=ip:port,host2:port=ip:port". It lets tools
// running on the node reach cluster Services by their in-cluster DNS names (so TLS
// server-name checks and DPoP htu values stay identical) without editing /etc/hosts.
func ParseDialOverrides(spec string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		from, to, ok := strings.Cut(item, "=")
		if !ok {
			return nil, fmt.Errorf("dial override %q is not host:port=ip:port", item)
		}
		out[strings.TrimSpace(from)] = strings.TrimSpace(to)
	}
	return out, nil
}

// NewTransport returns an HTTP/1.1 transport using tlsConf and the dial overrides.
func NewTransport(tlsConf *tls.Config, overrides map[string]string) *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if target, ok := overrides[addr]; ok {
				addr = target
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsConf,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
}

// NormalizeHTU canonicalises a URL for DPoP htu comparison (RFC 9449 §4.3): scheme
// and host lower-cased, default port removed, query and fragment dropped.
func NormalizeHTU(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("htu %q is not an absolute URL", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

// CurvePreferences returns the TLS key-exchange groups to offer. With pqOnly the
// connection must use the hybrid ML-KEM group X25519MLKEM768 (RFC 9370 style hybrid
// of X25519 and ML-KEM-768), so a classical-only peer fails the handshake instead of
// silently negotiating a quantum-vulnerable key exchange. Otherwise Go's default
// order applies, which already prefers X25519MLKEM768 and falls back to X25519.
func CurvePreferences(pqOnly bool) []tls.CurveID {
	if pqOnly {
		return []tls.CurveID{tls.X25519MLKEM768}
	}
	return nil
}

// IsPQKex reports whether a negotiated group provides post-quantum key exchange.
func IsPQKex(id tls.CurveID) bool { return id == tls.X25519MLKEM768 }
EOF
```


```bash
cat > ~/pqc-xapp-auth/internal/config/env.go <<'EOF'
// Package config reads component configuration from environment variables,
// collecting every problem so a misconfigured pod reports all of them at once.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Env accumulates parse errors while reading variables.
type Env struct {
	errs []error
}

func (e *Env) lookup(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

// Str returns the variable or def when unset.
func (e *Env) Str(key, def string) string {
	if v, ok := e.lookup(key); ok {
		return v
	}
	return def
}

// Req returns the variable and records an error when it is unset.
func (e *Env) Req(key string) string {
	v, ok := e.lookup(key)
	if !ok {
		e.errs = append(e.errs, fmt.Errorf("%s is required", key))
	}
	return v
}

// Dur parses a Go duration (e.g. 15m, 168h).
func (e *Env) Dur(key string, def time.Duration) time.Duration {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return d
}

// Int parses a decimal integer.
func (e *Env) Int(key string, def int) int {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return n
}

// Bool parses true/false/1/0.
func (e *Env) Bool(key string, def bool) bool {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		e.errs = append(e.errs, fmt.Errorf("%s: %w", key, err))
		return def
	}
	return b
}

// List splits a comma-separated variable, dropping empty items.
func (e *Env) List(key string, def []string) []string {
	v, ok := e.lookup(key)
	if !ok {
		return def
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Fail records a validation error discovered by the caller.
func (e *Env) Fail(format string, args ...any) {
	e.errs = append(e.errs, fmt.Errorf(format, args...))
}

// Err returns all accumulated errors, or nil.
func (e *Env) Err() error {
	return errors.Join(e.errs...)
}
EOF
```


```bash
cat > ~/pqc-xapp-auth/internal/logx/logx.go <<'EOF'
// Package logx builds the structured (JSON) logger used by every component.
package logx

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a JSON logger tagged with the component name. LOG_LEVEL selects the level.
func New(component string) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h).With("component", component)
}
EOF
```


## 2.3 The test

This is the verification for the chunk and evidence for the write-up: the RFC 7638
reference vector, all five algorithms through one code path, ML-DSA producing RFC 9964
AKP keys, and the `none` / HMAC / private-key attacks refused.

```bash
cat > ~/pqc-xapp-auth/internal/jose/jose_test.go <<'EOF'
package jose

import (
	"strings"
	"testing"
)

// RFC 7638 section 3.1 example key and thumbprint, computed through the library.
func TestThumbprintRFC7638(t *testing.T) {
	k := JWK{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	got, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint %s, want %s", got, want)
	}
}

// Every supported algorithm, classical and post-quantum, goes through the same code.
func TestSignVerifyAllAlgorithms(t *testing.T) {
	for _, alg := range []string{"ES256", "ES384", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(alg, func(t *testing.T) {
			signer, err := GenerateSigner(alg)
			if err != nil {
				t.Fatal(err)
			}
			if signer.Alg() != alg {
				t.Fatalf("signer alg %q, want %q", signer.Alg(), alg)
			}
			compact, err := signer.SignCompact(map[string]any{"typ": "dpop+jwt", "jwk": signer.PublicKey()}, map[string]any{"htm": "GET"})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCompact(compact)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Alg() != alg || parsed.Typ() != "dpop+jwt" {
				t.Fatalf("header alg=%q typ=%q", parsed.Alg(), parsed.Typ())
			}
			// The proof key travels in the header, exactly as a DPoP proof carries it.
			rawJWK, ok := parsed.Header["jwk"].(map[string]any)
			if !ok {
				t.Fatalf("jwk header missing: %#v", parsed.Header)
			}
			pub, err := JWK(rawJWK).PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := parsed.VerifySignature(pub); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			// Thumbprint of the header key must equal the signer's (cnf.jkt check).
			hdrThumb, err := JWK(rawJWK).Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			ownThumb, err := signer.PublicJWK().Thumbprint()
			if err != nil {
				t.Fatal(err)
			}
			if hdrThumb != ownThumb {
				t.Fatalf("thumbprint mismatch: header %s, signer %s", hdrThumb, ownThumb)
			}
			// A signature made by another key of the same algorithm must not verify.
			other, err := GenerateSigner(alg)
			if err != nil {
				t.Fatal(err)
			}
			forged, err := other.SignCompact(map[string]any{"typ": "dpop+jwt"}, map[string]any{"htm": "GET"})
			if err != nil {
				t.Fatal(err)
			}
			swapped, err := ParseCompact(strings.Join([]string{
				strings.Split(compact, ".")[0], strings.Split(compact, ".")[1], strings.Split(forged, ".")[2]}, "."))
			if err != nil {
				t.Fatal(err)
			}
			if err := swapped.VerifySignature(pub); err == nil {
				t.Fatal("signature from another key was accepted")
			}
		})
	}
}

// ML-DSA keys must serialise as RFC 9964 AKP keys.
func TestMLDSAKeyIsAKP(t *testing.T) {
	signer, err := GenerateSigner("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicJWK()
	if pub.Str("kty") != "AKP" {
		t.Fatalf("kty %q, want AKP", pub.Str("kty"))
	}
	if pub.Str("alg") != "ML-DSA-65" {
		t.Fatalf("alg %q, want ML-DSA-65", pub.Str("alg"))
	}
	if pub.Str("pub") == "" {
		t.Fatal("AKP key has no pub member")
	}
	if _, has := pub["priv"]; has {
		t.Fatal("public AKP key leaked the priv member")
	}
	if _, err := pub.Thumbprint(); err != nil {
		t.Fatalf("AKP thumbprint: %v", err)
	}
}

func TestRejectsNoneSymmetricAndPrivateJWK(t *testing.T) {
	if _, err := LookupAlg("none"); err == nil {
		t.Fatal(`alg "none" accepted`)
	}
	if _, err := LookupAlg("HS256"); err == nil {
		t.Fatal("symmetric alg accepted")
	}
	signer, _ := GenerateSigner("ML-DSA-44")
	k := JWK{}
	for m, v := range signer.PublicJWK() {
		k[m] = v
	}
	k["priv"] = "AAAA"
	if _, err := k.PublicKey(); err == nil {
		t.Fatal("JWK carrying private material accepted as a verification key")
	}
}
EOF
```


## 2.4 Build and verify

```bash
cd ~/pqc-xapp-auth && for f in internal/jose/jose.go:132 internal/jose/jws.go:91 internal/jose/signer.go:110 internal/jose/jwks.go:104 internal/netx/netx.go:94 internal/config/env.go:107 internal/logx/logx.go:23 internal/jose/jose_test.go:133; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `internal/jose/jose.go` | 132 |
| `internal/jose/jws.go` | 91 |
| `internal/jose/signer.go` | 110 |
| `internal/jose/jwks.go` | 104 |
| `internal/netx/netx.go` | 94 |
| `internal/config/env.go` | 107 |
| `internal/logx/logx.go` | 23 |
| `internal/jose/jose_test.go` | 133 |


```bash
cd ~/pqc-xapp-auth && go mod tidy && go build -p=2 ./...
```

```bash
cd ~/pqc-xapp-auth && go test -p=2 -v ./internal/jose/ 2>&1 | tail -30
```

All four tests must pass, including the five algorithm sub-tests. If
`TestThumbprintRFC7638` passes, your thumbprint implementation matches the RFC's own
worked example — that is the value that ends up in `cnf.jkt`.

Next: `chunk-03a-ca-code.md`.
