# Chunk 6A - The validator

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.
>
> **Paste one `cat >` block at a time.** Each file has its own heredoc terminator, but
> pasting several blocks in one go still risks the shell pairing them wrongly.
>
> **If a directory listing appears while you paste**, your terminal is treating the
> tab characters in Go source as tab-completion. Fix it before continuing:
> `bind 'set enable-bracketed-paste on'`, or `bind 'set disable-completion on'` on an
> older readline. Verify with `printf '\tx\n' > /tmp/t; cat -A /tmp/t` showing `^Ix$`.


**Goal:** the resource-side enforcement point - the component that decides whether a
request is allowed. This is the core of the contribution.

**Needs the cluster?** No. Everything here is unit-tested offline.

---

## Why this chunk is the one that matters

Chunks 1 to 5 produce credentials and tokens. None of them *check* anything. A token
with `cnf.x5t#S256` in it is just a string until something compares that value against
the certificate on the connection. This chunk is that something.

Three design decisions worth being able to defend:

- **Fail closed, with a reason code.** Every rejection returns a machine-readable
  `reason_code` and a human-readable detail. The reason codes are not decoration: they
  are what the 46-case suite in Chunk 6C asserts on, and what makes a failure
  diagnosable in a log instead of a guess.
- **Local validation and introspection are the same checks.** `ModeLocal` verifies the
  JWT signature against JWKS; `ModeIntrospection` asks the authorization server
  (RFC 7662). Everything after that - audience, scope, role, expiry, and the binding -
  is identical code. That is what makes the latency comparison in Chunk 11 meaningful:
  it measures the architectural choice, not two different implementations.
- **One validator, two transports.** `Authorize` takes an `*http.Request`.
  `AuthorizeChannel` (6A.6) builds a synthetic request whose `TLS.PeerCertificates` is
  the chain from the sidecar's post-quantum tunnel handshake, and calls the same
  `Authorize`. RMR traffic over a tunnel gets the same enforcement as HTTP over TLS,
  because it *is* the same enforcement.

## 6A.1 Configuration

`ChannelMode` is read here even though nothing uses it until Chunk 10. That is
deliberate - the validator is transport-agnostic from the start.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/config.go <<'XAPP_RESOURCE_CONFIG_GO_EOF'
// Package xappresource enforces sender-constrained access tokens at the resource xApp.
//
// Keycloak only issues bound tokens; nothing checks the binding unless the resource
// does. Validator.Middleware is the single enforcement point:
//
//	cnf.x5t#S256 (Methods A/B, RFC 8705): the TLS peer certificate's SHA-256 thumbprint must match.
//	cnf.jkt      (Method C, RFC 9449):    a valid DPoP proof signed by the key whose JWK thumbprint matches,
//	                                      with ath, htm, htu, iat and a never-seen jti.
//
// Token validity is established either locally (JWS signature via JWKS + exp/nbf/iss/aud)
// or by RFC 7662 introspection; the binding checks are identical in both modes.
// Everything fails closed: a missing, malformed or unrecognised cnf is a rejection.
package xappresource

import (
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
)

// Config configures a Validator. ConfigFromEnv reads it from the environment.
type Config struct {
	Issuer        string
	Audience      string
	JWKSURL       string
	RequiredScope string
	RequiredRole  string
	TrustBundle   []string // PEM trust anchors for client certificates (RIC intermediate CAs)

	ClockSkew       time.Duration
	DPoPProofWindow time.Duration // accepted age of a proof's iat
	ReplayCacheSize int
	DPoPAllowedAlgs []string // empty = any asymmetric alg registered in the jose package

	PublicBaseURL string // optional external base URL used to reconstruct htu

	// ChannelMode selects how tunnel traffic is validated (AuthorizeChannel).
	ChannelMode Mode

	IntrospectionURL      string
	IntrospectionClientID string

	JWKSCacheTTL   time.Duration
	JWKSMinRefresh time.Duration
}

// ConfigFromEnv reads the validator configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		Issuer:                e.Req("TOKEN_ISSUER"),
		Audience:              e.Req("TOKEN_AUDIENCE"),
		JWKSURL:               e.Req("JWKS_URL"),
		RequiredScope:         e.Str("REQUIRED_SCOPE", ""),
		RequiredRole:          e.Str("REQUIRED_ROLE", ""),
		TrustBundle:           e.List("RIC_TRUST_BUNDLE", nil),
		ClockSkew:             e.Dur("CLOCK_SKEW", 30*time.Second),
		DPoPProofWindow:       e.Dur("DPOP_PROOF_WINDOW", 60*time.Second),
		ReplayCacheSize:       e.Int("DPOP_REPLAY_CACHE_SIZE", 1_000_000),
		DPoPAllowedAlgs:       e.List("DPOP_ALLOWED_ALGS", nil),
		PublicBaseURL:         e.Str("PUBLIC_BASE_URL", ""),
		ChannelMode:           Mode(e.Str("CHANNEL_VALIDATION_MODE", string(ModeLocal))),
		IntrospectionURL:      e.Str("INTROSPECTION_URL", ""),
		IntrospectionClientID: e.Str("XAPP_CLIENT_ID", ""),
		JWKSCacheTTL:          e.Dur("JWKS_CACHE_TTL", 5*time.Minute),
		JWKSMinRefresh:        e.Dur("JWKS_MIN_REFRESH", 10*time.Second),
	}
	if len(c.TrustBundle) == 0 {
		e.Fail("RIC_TRUST_BUNDLE is required")
	}
	return c, e.Err()
}
XAPP_RESOURCE_CONFIG_GO_EOF
```


## 6A.2 Rejection reasons

The complete list of ways a request can be refused. Read it once: it is the threat
model, written as code.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/reasons.go <<'XAPP_RESOURCE_REASONS_GO_EOF'
package xappresource

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Rejection reason codes. Each rejection carries one code plus a human-readable detail.
const (
	ReasonAuthorizationMissing   = "authorization_missing"
	ReasonAuthorizationMalformed = "authorization_malformed"
	ReasonSchemeUnsupported      = "authorization_scheme_unsupported"

	ReasonTokenMalformed        = "token_malformed"
	ReasonTokenKeyUnavailable   = "token_key_unavailable"
	ReasonTokenSignatureInvalid = "token_signature_invalid"
	ReasonTokenExpired          = "token_expired"
	ReasonTokenNotYetValid      = "token_not_yet_valid"
	ReasonTokenIssuerMismatch   = "token_issuer_mismatch"
	ReasonTokenAudienceMismatch = "token_audience_mismatch"
	ReasonTokenInactive         = "token_inactive"
	ReasonIntrospectionFailed   = "introspection_failed"
	ReasonInsufficientScope     = "insufficient_scope"

	ReasonCnfMissing      = "cnf_missing"
	ReasonCnfMalformed    = "cnf_malformed"
	ReasonCnfUnrecognized = "cnf_unrecognized"

	ReasonClientCertMissing    = "client_certificate_missing"
	ReasonClientCertExpired    = "client_certificate_expired"
	ReasonClientCertInvalid    = "client_certificate_invalid"
	ReasonX5tMismatch          = "cnf_x5t_mismatch"
	ReasonCertBoundWrongScheme = "cert_bound_token_wrong_scheme"

	ReasonDPoPAsBearer        = "dpop_token_used_as_bearer"
	ReasonDPoPProofMissing    = "dpop_proof_missing"
	ReasonDPoPProofMultiple   = "dpop_proof_multiple"
	ReasonDPoPProofMalformed  = "dpop_proof_malformed"
	ReasonDPoPProofType       = "dpop_proof_wrong_typ"
	ReasonDPoPProofAlg        = "dpop_proof_alg_not_allowed"
	ReasonDPoPProofJWK        = "dpop_proof_jwk_invalid"
	ReasonDPoPProofSignature  = "dpop_proof_signature_invalid"
	ReasonDPoPJktMismatch     = "dpop_jkt_mismatch"
	ReasonDPoPAthMissing      = "dpop_ath_missing"
	ReasonDPoPAthMismatch     = "dpop_ath_mismatch"
	ReasonDPoPHtmMismatch     = "dpop_htm_mismatch"
	ReasonDPoPHtuMismatch     = "dpop_htu_mismatch"
	ReasonDPoPIatOutOfWindow  = "dpop_iat_out_of_window"
	ReasonDPoPJtiMissing      = "dpop_jti_missing"
	ReasonDPoPReplayed        = "dpop_proof_replayed"
	ReasonDPoPReplayCacheFull = "dpop_replay_cache_full"
)

// Rejection is a fail-closed authorization decision.
type Rejection struct {
	Status int
	Code   string
	Detail string
	DPoP   bool // challenge with the DPoP scheme
}

func (r *Rejection) Error() string { return r.Code + ": " + r.Detail }

func reject(code, format string, args ...any) *Rejection {
	status := http.StatusUnauthorized
	if code == ReasonInsufficientScope {
		status = http.StatusForbidden
	}
	return &Rejection{Status: status, Code: code, Detail: fmt.Sprintf(format, args...), DPoP: strings.HasPrefix(code, "dpop_")}
}

// RejectionBody is the JSON body returned with every rejection.
type RejectionBody struct {
	Error      string `json:"error"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

func writeRejection(w http.ResponseWriter, r *Rejection) {
	errCode := "invalid_token"
	switch {
	case r.Code == ReasonInsufficientScope:
		errCode = "insufficient_scope"
	case strings.HasPrefix(r.Code, "dpop_proof") || r.Code == ReasonDPoPJktMismatch || strings.HasPrefix(r.Code, "dpop_ath") ||
		r.Code == ReasonDPoPHtmMismatch || r.Code == ReasonDPoPHtuMismatch || r.Code == ReasonDPoPIatOutOfWindow || r.Code == ReasonDPoPJtiMissing:
		errCode = "invalid_dpop_proof"
	}
	scheme := "Bearer"
	if r.DPoP {
		scheme = "DPoP"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`%s error=%q, error_description=%q`, scheme, errCode, r.Code))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.Status)
	_ = json.NewEncoder(w).Encode(RejectionBody{Error: errCode, ReasonCode: r.Code, Reason: r.Detail})
}
XAPP_RESOURCE_REASONS_GO_EOF
```


## 6A.3 The replay cache

DPoP proofs are single-use. The cache is keyed on `jti` plus the proof key
thumbprint, so two different clients cannot collide, and it is swept on insert so it
cannot grow without bound.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/replay.go <<'XAPP_RESOURCE_REPLAY_GO_EOF'
package xappresource

import (
	"sync"
	"time"
)

// ReplayCache remembers DPoP proof identifiers until their acceptance window has
// passed. When full it refuses new entries (fail closed) after sweeping expired ones.
type ReplayCache struct {
	mu        sync.Mutex
	entries   map[string]time.Time
	max       int
	lastSweep time.Time
}

// NewReplayCache creates a cache holding at most max identifiers.
func NewReplayCache(max int) *ReplayCache {
	return &ReplayCache{entries: make(map[string]time.Time), max: max}
}

// Result of CheckAndStore.
const (
	ReplayFresh = iota
	ReplaySeen
	ReplayFull
)

// CheckAndStore records key until expiry unless it is already present and unexpired.
func (c *ReplayCache) CheckAndStore(key string, expiry, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.entries[key]; ok && now.Before(exp) {
		return ReplaySeen
	}
	if len(c.entries) >= c.max || now.Sub(c.lastSweep) > 10*time.Second {
		for k, exp := range c.entries {
			if !now.Before(exp) {
				delete(c.entries, k)
			}
		}
		c.lastSweep = now
		if len(c.entries) >= c.max {
			return ReplayFull
		}
	}
	c.entries[key] = expiry
	return ReplayFresh
}

// Len returns the number of stored identifiers.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
XAPP_RESOURCE_REPLAY_GO_EOF
```


## 6A.4 Introspection mode

Note that the introspection client authenticates with the xApp's own mTLS identity.
The resource server is an OAuth client too.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/introspect.go <<'XAPP_RESOURCE_INTROSPECT_GO_EOF'
package xappresource

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Introspector calls the RFC 7662 introspection endpoint, authenticating as the
// resource xApp's own client over its mTLS identity.
type Introspector struct {
	URL      string
	ClientID string
	Client   *http.Client
}

// Introspect returns the claims of an active token, or a rejection.
func (i *Introspector) Introspect(ctx context.Context, token string) (map[string]any, *Rejection) {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}, "client_id": {i.ClientID}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, i.URL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := i.Client.Do(req)
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint unreachable: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, reject(ReasonIntrospectionFailed, "read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, reject(ReasonIntrospectionFailed, "introspection endpoint returned HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, reject(ReasonIntrospectionFailed, "introspection response is not a JSON object")
	}
	if active, _ := claims["active"].(bool); !active {
		return nil, reject(ReasonTokenInactive, "authorization server reports the token as inactive (expired, revoked, or not issued by it)")
	}
	return claims, nil
}
XAPP_RESOURCE_INTROSPECT_GO_EOF
```


## 6A.5 The validator

The order of the checks matters. Signature or introspection first, then the standard
claims, then the binding - so a forged token never reaches the binding comparison and
a reason code never leaks information about a token that was not genuine.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/validator.go <<'XAPP_RESOURCE_VALIDATOR_GO_EOF'
package xappresource

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// Mode selects how token validity is established.
type Mode string

// Validation modes.
const (
	ModeLocal         Mode = "local"
	ModeIntrospection Mode = "introspection"
)

// Principal describes an authorized caller; it is stored in the request context.
type Principal struct {
	ClientID   string
	Subject    string
	Scopes     []string
	Binding    string // "x5t#S256" or "jkt"
	Thumbprint string
	Mode       Mode
	Claims     map[string]any
}

type principalKey struct{}

// PrincipalFrom returns the authorized caller placed in ctx by the middleware.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// Validator is the resource-side enforcement point.
type Validator struct {
	cfg        Config
	log        *slog.Logger
	keys       *jose.KeySet
	roots      *x509.CertPool
	replay     *ReplayCache
	introspect *Introspector
	algs       map[string]bool
	now        func() time.Time
}

// NewValidator builds a validator. httpClient is the resource xApp's own mTLS client,
// used to fetch the JWKS and to call introspection.
func NewValidator(cfg Config, httpClient *http.Client, log *slog.Logger) (*Validator, error) {
	roots, err := pki.LoadCertPool(cfg.TrustBundle...)
	if err != nil {
		return nil, fmt.Errorf("client certificate trust bundle: %w", err)
	}
	v := &Validator{
		cfg:    cfg,
		log:    log.With("component", "xapp-resource"),
		keys:   jose.NewKeySet(cfg.JWKSURL, httpClient, cfg.JWKSCacheTTL, cfg.JWKSMinRefresh),
		roots:  roots,
		replay: NewReplayCache(cfg.ReplayCacheSize),
		algs:   map[string]bool{},
		now:    time.Now,
	}
	for _, a := range cfg.DPoPAllowedAlgs {
		v.algs[a] = true
	}
	if cfg.IntrospectionURL != "" {
		v.introspect = &Introspector{URL: cfg.IntrospectionURL, ClientID: cfg.IntrospectionClientID, Client: httpClient}
	}
	return v, nil
}

// Middleware enforces the token and its binding before calling next.
func (v *Validator) Middleware(mode Mode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		p, rej := v.Authorize(r, mode)
		elapsed := float64(time.Since(start).Microseconds()) / 1000
		if rej != nil {
			v.log.Warn("authz_rejected",
				"reason_code", rej.Code, "reason", rej.Detail, "mode", mode,
				"http_method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr, "validation_ms", elapsed)
			writeRejection(w, rej)
			return
		}
		v.log.Debug("authz_granted",
			"client_id", p.ClientID, "binding", p.Binding, "cnf", p.Thumbprint, "mode", mode,
			"http_method", r.Method, "path", r.URL.Path, "validation_ms", elapsed)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// Authorize runs every check and returns the caller or the first failure.
func (v *Validator) Authorize(r *http.Request, mode Mode) (*Principal, *Rejection) {
	scheme, token, rej := parseAuthorization(r)
	if rej != nil {
		return nil, rej
	}

	// 1. Token validity (signature/exp/nbf/iss/aud locally, or introspection).
	var claims map[string]any
	switch mode {
	case ModeLocal:
		claims, rej = v.validateLocally(r.Context(), token)
	case ModeIntrospection:
		if v.introspect == nil {
			return nil, reject(ReasonIntrospectionFailed, "introspection is not configured")
		}
		claims, rej = v.introspect.Introspect(r.Context(), token)
		if rej == nil {
			rej = v.checkIssuerAudience(claims)
		}
	default:
		return nil, reject(ReasonIntrospectionFailed, "unknown validation mode %q", mode)
	}
	if rej != nil {
		return nil, rej
	}

	// 2. Authorization claims.
	if rej := v.checkAuthorization(claims); rej != nil {
		return nil, rej
	}

	// 3. Sender constraint. Absent or unusable cnf is a rejection, never a pass-through.
	rawCnf, present := claims["cnf"]
	if !present {
		return nil, reject(ReasonCnfMissing, "access token has no cnf claim; unbound bearer tokens are not accepted")
	}
	cnf, ok := rawCnf.(map[string]any)
	if !ok {
		return nil, reject(ReasonCnfMalformed, "cnf claim is not a JSON object")
	}
	x5t, hasX5t, rej := cnfString(cnf, "x5t#S256")
	if rej != nil {
		return nil, rej
	}
	jkt, hasJkt, rej := cnfString(cnf, "jkt")
	if rej != nil {
		return nil, rej
	}
	if !hasX5t && !hasJkt {
		return nil, reject(ReasonCnfUnrecognized, "cnf carries no supported confirmation method (x5t#S256 or jkt)")
	}

	p := &Principal{Mode: mode, Claims: claims}
	p.ClientID = firstString(claims, "client_id", "azp")
	p.Subject, _ = claims["sub"].(string)
	if s, ok := claims["scope"].(string); ok {
		p.Scopes = strings.Fields(s)
	}
	if hasX5t {
		if rej := v.checkCertificateBinding(r, scheme, x5t, hasJkt); rej != nil {
			return nil, rej
		}
		p.Binding, p.Thumbprint = "x5t#S256", x5t
	}
	if hasJkt {
		if rej := v.checkDPoPBinding(r, scheme, token, jkt); rej != nil {
			return nil, rej
		}
		p.Binding, p.Thumbprint = "jkt", jkt
	}
	return p, nil
}

func parseAuthorization(r *http.Request) (scheme, token string, rej *Rejection) {
	values := r.Header.Values("Authorization")
	if len(values) == 0 {
		return "", "", reject(ReasonAuthorizationMissing, "no Authorization header")
	}
	if len(values) > 1 {
		return "", "", reject(ReasonAuthorizationMalformed, "multiple Authorization headers")
	}
	s, t, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	t = strings.TrimSpace(t)
	if !ok || t == "" {
		return "", "", reject(ReasonAuthorizationMalformed, "Authorization header is not '<scheme> <token>'")
	}
	switch strings.ToLower(s) {
	case "bearer":
		return "bearer", t, nil
	case "dpop":
		return "dpop", t, nil
	}
	return "", "", reject(ReasonSchemeUnsupported, "authorization scheme %q is not supported", s)
}

func (v *Validator) validateLocally(ctx context.Context, token string) (map[string]any, *Rejection) {
	jws, err := jose.ParseCompact(token)
	if err != nil {
		return nil, reject(ReasonTokenMalformed, "access token is not a compact JWS: %v", err)
	}
	// The algorithm comes from the JWS header and is dispatched through the jose
	// registry; the key comes from the configured JWKS URL.
	key, err := v.keys.Key(ctx, jws.Kid(), jws.Alg())
	if err != nil {
		return nil, reject(ReasonTokenKeyUnavailable, "no verification key: %v", err)
	}
	if err := jws.VerifySignature(key); err != nil {
		return nil, reject(ReasonTokenSignatureInvalid, "access token signature (alg %s) invalid: %v", jws.Alg(), err)
	}
	claims, err := jws.Claims()
	if err != nil {
		return nil, reject(ReasonTokenMalformed, "access token payload is not a JSON object: %v", err)
	}
	now := v.now()
	exp, hasExp, err := numericClaim(claims, "exp")
	if err != nil || !hasExp {
		return nil, reject(ReasonTokenMalformed, "access token has no valid exp claim")
	}
	if now.After(time.Unix(exp, 0).Add(v.cfg.ClockSkew)) {
		return nil, reject(ReasonTokenExpired, "access token expired at %s", time.Unix(exp, 0).UTC().Format(time.RFC3339))
	}
	if nbf, ok, err := numericClaim(claims, "nbf"); err != nil {
		return nil, reject(ReasonTokenMalformed, "nbf claim is not numeric")
	} else if ok && now.Add(v.cfg.ClockSkew).Before(time.Unix(nbf, 0)) {
		return nil, reject(ReasonTokenNotYetValid, "access token not valid before %s", time.Unix(nbf, 0).UTC().Format(time.RFC3339))
	}
	if rej := v.checkIssuerAudience(claims); rej != nil {
		return nil, rej
	}
	return claims, nil
}

func (v *Validator) checkIssuerAudience(claims map[string]any) *Rejection {
	if iss, _ := claims["iss"].(string); iss != v.cfg.Issuer {
		return reject(ReasonTokenIssuerMismatch, "iss %q is not the trusted issuer %q", iss, v.cfg.Issuer)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud == v.cfg.Audience {
			return nil
		}
	case []any:
		for _, a := range aud {
			if s, _ := a.(string); s == v.cfg.Audience {
				return nil
			}
		}
	}
	return reject(ReasonTokenAudienceMismatch, "aud %v does not include %q", claims["aud"], v.cfg.Audience)
}

func (v *Validator) checkAuthorization(claims map[string]any) *Rejection {
	if want := v.cfg.RequiredScope; want != "" {
		scope, _ := claims["scope"].(string)
		if !slices.Contains(strings.Fields(scope), want) {
			return reject(ReasonInsufficientScope, "token scope %q lacks %q", scope, want)
		}
	}
	if want := v.cfg.RequiredRole; want != "" {
		var roles []any
		if ra, ok := claims["realm_access"].(map[string]any); ok {
			roles, _ = ra["roles"].([]any)
		}
		if !slices.ContainsFunc(roles, func(r any) bool { s, _ := r.(string); return s == want }) {
			return reject(ReasonInsufficientScope, "token realm roles %v lack %q", roles, want)
		}
	}
	return nil
}

// checkCertificateBinding implements RFC 8705 §3: the thumbprint of the certificate
// presented on this TLS session must equal cnf.x5t#S256.
func (v *Validator) checkCertificateBinding(r *http.Request, scheme, x5t string, alsoDPoP bool) *Rejection {
	if scheme != "bearer" && !alsoDPoP {
		return reject(ReasonCertBoundWrongScheme, "certificate-bound token must be sent with the Bearer scheme, got %q", scheme)
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return reject(ReasonClientCertMissing, "token is bound to certificate x5t#S256=%s but no client certificate was presented on the TLS session", x5t)
	}
	chain := r.TLS.PeerCertificates
	if kind, err := pki.VerifyChain(chain, v.roots, v.now(), x509.ExtKeyUsageClientAuth); err != nil {
		if kind == pki.ChainExpired {
			return reject(ReasonClientCertExpired, "%v", err)
		}
		return reject(ReasonClientCertInvalid, "client certificate rejected (%s): %v", kind, err)
	}
	got := pki.ThumbprintS256(chain[0])
	if subtle.ConstantTimeCompare([]byte(got), []byte(x5t)) != 1 {
		return reject(ReasonX5tMismatch, "presented certificate CN=%q x5t#S256=%s does not match token cnf.x5t#S256=%s",
			chain[0].Subject.CommonName, got, x5t)
	}
	return nil
}

// checkDPoPBinding implements RFC 9449 §4.3 and §7.1 for a protected resource request.
func (v *Validator) checkDPoPBinding(r *http.Request, scheme, token, jkt string) *Rejection {
	if scheme != "dpop" {
		return reject(ReasonDPoPAsBearer, "token is DPoP-bound (cnf.jkt=%s) but was presented with the %s scheme", jkt, scheme)
	}
	proofs := r.Header.Values("DPoP")
	if len(proofs) == 0 {
		return reject(ReasonDPoPProofMissing, "DPoP-bound token presented without a DPoP proof header")
	}
	if len(proofs) > 1 {
		return reject(ReasonDPoPProofMultiple, "more than one DPoP header")
	}
	proof, err := jose.ParseCompact(proofs[0])
	if err != nil {
		return reject(ReasonDPoPProofMalformed, "DPoP proof is not a compact JWS: %v", err)
	}
	if proof.Typ() != "dpop+jwt" {
		return reject(ReasonDPoPProofType, "DPoP proof typ is %q, expected dpop+jwt", proof.Typ())
	}
	if len(v.algs) > 0 && !v.algs[proof.Alg()] {
		return reject(ReasonDPoPProofAlg, "DPoP proof alg %q is not allowed", proof.Alg())
	}

	// (a) Proof signature, verified with the public key carried in its own jwk header.
	rawJWK, ok := proof.Header["jwk"].(map[string]any)
	if !ok {
		return reject(ReasonDPoPProofJWK, "DPoP proof header has no jwk")
	}
	jwk := jose.JWK(rawJWK)
	pub, err := jwk.PublicKey()
	if err != nil {
		return reject(ReasonDPoPProofJWK, "DPoP proof jwk unusable: %v", err)
	}
	if err := proof.VerifySignature(pub); err != nil {
		return reject(ReasonDPoPProofSignature, "DPoP proof signature (alg %s) invalid: %v", proof.Alg(), err)
	}

	// (b) The proof key is the key the token is bound to: JWK SHA-256 thumbprint == cnf.jkt.
	thumb, err := jwk.Thumbprint()
	if err != nil {
		return reject(ReasonDPoPProofJWK, "cannot compute JWK thumbprint: %v", err)
	}
	if subtle.ConstantTimeCompare([]byte(thumb), []byte(jkt)) != 1 {
		return reject(ReasonDPoPJktMismatch, "DPoP proof key thumbprint %s does not match token cnf.jkt %s", thumb, jkt)
	}

	claims, err := proof.Claims()
	if err != nil {
		return reject(ReasonDPoPProofMalformed, "DPoP proof payload: %v", err)
	}

	// (c) ath binds the proof to this access token.
	ath, _ := claims["ath"].(string)
	if ath == "" {
		return reject(ReasonDPoPAthMissing, "DPoP proof has no ath claim")
	}
	sum := sha256.Sum256([]byte(token))
	if want := jose.B64(sum[:]); subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
		return reject(ReasonDPoPAthMismatch, "DPoP proof ath %s is not the hash of the presented access token (%s)", ath, want)
	}

	// (d) htm/htu bind the proof to this request.
	if htm, _ := claims["htm"].(string); htm != r.Method {
		return reject(ReasonDPoPHtmMismatch, "DPoP proof htm %q does not match request method %q", htm, r.Method)
	}
	htuClaim, _ := claims["htu"].(string)
	gotHTU, errClaim := netx.NormalizeHTU(htuClaim)
	wantHTU, errReq := v.requestHTU(r)
	if errClaim != nil || errReq != nil || gotHTU != wantHTU {
		return reject(ReasonDPoPHtuMismatch, "DPoP proof htu %q does not match request URI %q", htuClaim, wantHTU)
	}

	// (e) Freshness and single use.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return reject(ReasonDPoPJtiMissing, "DPoP proof has no jti")
	}
	iatUnix, ok, err := numericClaim(claims, "iat")
	if err != nil || !ok {
		return reject(ReasonDPoPProofMalformed, "DPoP proof has no numeric iat")
	}
	now, iat := v.now(), time.Unix(iatUnix, 0)
	if iat.Before(now.Add(-v.cfg.DPoPProofWindow-v.cfg.ClockSkew)) || iat.After(now.Add(v.cfg.ClockSkew)) {
		return reject(ReasonDPoPIatOutOfWindow, "DPoP proof iat %s is outside the accepted window (%s, skew %s)",
			iat.UTC().Format(time.RFC3339), v.cfg.DPoPProofWindow, v.cfg.ClockSkew)
	}
	expiry := iat.Add(v.cfg.DPoPProofWindow + 2*v.cfg.ClockSkew)
	switch v.replay.CheckAndStore(jkt+":"+jti, expiry, now) {
	case ReplaySeen:
		return reject(ReasonDPoPReplayed, "DPoP proof jti %s has already been used with key %s", jti, jkt)
	case ReplayFull:
		return reject(ReasonDPoPReplayCacheFull, "replay cache is full; refusing to accept unverifiable proofs")
	}
	return nil
}

func (v *Validator) requestHTU(r *http.Request) (string, error) {
	if base := v.cfg.PublicBaseURL; base != "" {
		return netx.NormalizeHTU(strings.TrimRight(base, "/") + r.URL.EscapedPath())
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return netx.NormalizeHTU(scheme + "://" + r.Host + r.URL.EscapedPath())
}

func cnfString(cnf map[string]any, name string) (string, bool, *Rejection) {
	raw, present := cnf[name]
	if !present {
		return "", false, nil
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false, reject(ReasonCnfMalformed, "cnf member %q is not a non-empty string", name)
	}
	return s, true, nil
}

func numericClaim(claims map[string]any, name string) (int64, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	switch n := raw.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true, nil
		}
		f, err := n.Float64()
		return int64(f), err == nil, err
	case float64:
		return int64(n), true, nil
	}
	return 0, false, fmt.Errorf("claim %q is not numeric", name)
}

func firstString(claims map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := claims[n].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
XAPP_RESOURCE_VALIDATOR_GO_EOF
```


## 6A.6 Authorizing a channel that is not HTTP

**This file was missing from the first version of this chunk.** Without it the sidecar
in Chunk 10 does not compile, and the omission is only discovered four chunks later.

`AuthorizeChannel` is 50 lines of adaptation, not a second implementation. It builds
an `*http.Request` whose TLS state carries the tunnel peer's certificate chain, then
calls `Authorize`. The one genuinely new idea is `ChannelOperation = "TUNNEL"`: the
`htm` value is deliberately not an HTTP method, so a proof minted for a tunnel can
never be replayed against an HTTP resource, or the other way round.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/channel.go <<'XAPP_RESOURCE_CHANNEL_GO_EOF'
package xappresource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ChannelRequest is one authorization attempt on a channel that is not HTTP over
// TLS: the sidecar post-quantum tunnel, which carries RMR and HTTP alike.
//
// The checks are identical to the HTTP ones, because they are the same checks: the
// certificate the peer proved possession of during the tunnel handshake takes the
// place of the TLS peer certificate, and the authorization frame sent as the first
// record on the tunnel takes the place of the Authorization and DPoP headers.
type ChannelRequest struct {
	// Token is the access token the peer presented.
	Token string
	// Proof is the DPoP proof for a jkt-bound token (method C); empty for a
	// certificate-bound token (methods A and B).
	Proof string
	// PeerChain is the certificate chain the peer authenticated with, leaf first.
	PeerChain []*x509.Certificate
	// Target is the canonical URI of the destination, for example
	// https://xapp-b.ricxapp.svc.cluster.local:4570/rmr. It is what the proof
	// must carry in htu.
	Target string
	// Operation is what the proof must carry in htm; the sidecar uses TUNNEL.
	Operation string
}

// ChannelOperation is the htm value used for a tunnel authorization frame. It is not
// an HTTP method precisely because this is not an HTTP request, so a proof minted for
// a tunnel can never be replayed against an HTTP resource and the other way round.
const ChannelOperation = "TUNNEL"

// AuthorizeChannel runs every check Authorize runs, against a tunnel peer instead of
// a TLS peer. It returns the authorized caller or the first failure.
func (v *Validator) AuthorizeChannel(ctx context.Context, cr ChannelRequest) (*Principal, *Rejection) {
	if cr.Token == "" {
		return nil, reject(ReasonAuthorizationMissing, "authorization frame carries no access token")
	}
	u, err := url.Parse(cr.Target)
	if err != nil || u.Host == "" {
		return nil, reject(ReasonDPoPHtuMismatch, "channel target %q is not an absolute URI", cr.Target)
	}
	op := cr.Operation
	if op == "" {
		op = ChannelOperation
	}
	scheme := "Bearer"
	if cr.Proof != "" {
		scheme = "DPoP"
	}
	req := &http.Request{
		Method: op,
		URL:    u,
		Host:   u.Host,
		Header: http.Header{"Authorization": {scheme + " " + cr.Token}},
		// A non-nil TLS state is how the validator learns the peer certificate. The
		// tunnel established it with ML-KEM and ML-DSA rather than with TLS, but the
		// binding check is the same comparison against the same chain.
		TLS: &tls.ConnectionState{PeerCertificates: cr.PeerChain},
	}
	if cr.Proof != "" {
		req.Header.Set("DPoP", cr.Proof)
	}
	return v.Authorize(req.WithContext(ctx), v.channelMode())
}

// channelMode is the validation mode used for tunnel traffic.
func (v *Validator) channelMode() Mode {
	if v.introspect != nil && v.cfg.ChannelMode == ModeIntrospection {
		return ModeIntrospection
	}
	return ModeLocal
}

// ChannelTarget builds the canonical target URI for a tunnel route.
func ChannelTarget(host string, port int, route string) string {
	return fmt.Sprintf("https://%s:%d/%s", host, port, route)
}

// ChannelProofWindow is the accepted age of a tunnel authorization proof.
func (v *Validator) ChannelProofWindow() time.Duration { return v.cfg.DPoPProofWindow }
XAPP_RESOURCE_CHANNEL_GO_EOF
```


## 6A.7 The unit tests

```bash
cat > ~/pqc-xapp-auth/xapp-resource/validator_test.go <<'XAPP_RESOURCE_VALIDATOR_TEST_GO_EOF'
package xappresource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
)

// Offline end-to-end check of the validator: in-memory CA, JWKS server, token signer
// and a TLS resource server requesting client certificates.

type fixture struct {
	t        *testing.T
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	issuer   jose.Signer
	kid      string
	v        *Validator
	resource *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, kid: "test-kid"}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test RIC CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.caKey.PublicKey, f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	dir := t.TempDir()
	trust := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(trust, pki.EncodeCertsPEM(f.ca), 0o644)

	f.issuer, _ = jose.GenerateSigner("ES256")
	jwk := jose.JWK{}
	for k, v := range f.issuer.PublicJWK() {
		jwk[k] = v
	}
	jwk["kid"], jwk["use"], jwk["alg"] = f.kid, "sig", "ES256"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
	}))
	t.Cleanup(jwks.Close)

	v, err := NewValidator(Config{
		Issuer: "https://issuer.test/realms/ric", Audience: "ric-xapps", JWKSURL: jwks.URL,
		RequiredScope: "ric-sdl-access", TrustBundle: []string{trust}, ClockSkew: 5 * time.Second,
		DPoPProofWindow: 60 * time.Second, ReplayCacheSize: 1000, JWKSCacheTTL: time.Minute, JWKSMinRefresh: time.Second,
	}, jwks.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	f.resource = httptest.NewUnstartedServer(v.Middleware(ModeLocal, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	f.resource.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	f.resource.StartTLS()
	t.Cleanup(f.resource.Close)
	return f
}

func (f *fixture) leaf(cn string, lifetime time.Duration) *tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca, &key.PublicKey, f.caKey)
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (f *fixture) token(cnf map[string]any) string {
	claims := map[string]any{"iss": "https://issuer.test/realms/ric", "aud": "ric-xapps", "scope": "ric-sdl-access",
		"exp": time.Now().Add(5 * time.Minute).Unix(), "azp": "xapp-test"}
	if cnf != nil {
		claims["cnf"] = cnf
	}
	tok, err := f.issuer.SignCompact(map[string]any{"kid": f.kid, "typ": "JWT"}, claims)
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

func (f *fixture) do(cert *tls.Certificate, headers map[string]string) (int, string) {
	pool := x509.NewCertPool()
	pool.AddCert(f.resource.Certificate())
	conf := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true}}
	req, _ := http.NewRequest(http.MethodGet, f.resource.URL+"/api/v1/sdl/k", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body RejectionBody
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body.ReasonCode
}

func expect(t *testing.T, name string, status int, code string, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || code != wantCode {
		t.Errorf("%s: got %d %q, want %d %q", name, status, code, wantStatus, wantCode)
	}
}

func TestCertificateBinding(t *testing.T) {
	f := newFixture(t)
	a, b := f.leaf("xapp-a", time.Hour), f.leaf("xapp-b", time.Hour)
	tok := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(a.Leaf)})
	auth := map[string]string{"Authorization": "Bearer " + tok}

	s, c := f.do(a, auth)
	expect(t, "own certificate", s, c, 200, "")
	s, c = f.do(b, auth)
	expect(t, "other certificate", s, c, 401, ReasonX5tMismatch)
	s, c = f.do(nil, auth)
	expect(t, "no certificate", s, c, 401, ReasonClientCertMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(nil)})
	expect(t, "no cnf", s, c, 401, ReasonCnfMissing)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"x5t#S256": 42})})
	expect(t, "malformed cnf", s, c, 401, ReasonCnfMalformed)
	s, c = f.do(a, map[string]string{"Authorization": "Bearer " + f.token(map[string]any{"foo": "bar"})})
	expect(t, "unrecognised cnf", s, c, 401, ReasonCnfUnrecognized)
}

func TestDPoPBinding(t *testing.T) {
	f := newFixture(t)
	key, _ := jose.GenerateSigner("ES256")
	jkt, _ := key.PublicJWK().Thumbprint()
	tok := f.token(map[string]any{"jkt": jkt})
	url := f.resource.URL + "/api/v1/sdl/k"

	proof, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, tok, "", time.Now())
	s, c := f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "valid proof", s, c, 200, "")
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": proof})
	expect(t, "replayed proof", s, c, 401, ReasonDPoPReplayed)

	other, _ := jose.GenerateSigner("ES256")
	p2, _ := xappclient.BuildDPoPProof(other, http.MethodGet, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p2})
	expect(t, "foreign key", s, c, 401, ReasonDPoPJktMismatch)

	p3, _ := xappclient.BuildDPoPProof(key, http.MethodGet, url, f.token(map[string]any{"jkt": jkt}), "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p3})
	expect(t, "ath of other token", s, c, 401, ReasonDPoPAthMismatch)

	p4, _ := xappclient.BuildDPoPProof(key, http.MethodPost, url, tok, "", time.Now())
	s, c = f.do(nil, map[string]string{"Authorization": "DPoP " + tok, "DPoP": p4})
	expect(t, "wrong htm", s, c, 401, ReasonDPoPHtmMismatch)

	s, c = f.do(nil, map[string]string{"Authorization": "Bearer " + tok})
	expect(t, "used as bearer", s, c, 401, ReasonDPoPAsBearer)
}
XAPP_RESOURCE_VALIDATOR_TEST_GO_EOF
```


The channel tests reuse `newFixture`, `f.leaf` and `f.token` from the file above, so
they must be pasted after it.

```bash
cat > ~/pqc-xapp-auth/xapp-resource/channel_test.go <<'XAPP_RESOURCE_CHANNEL_TEST_GO_EOF'
package xappresource

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

const channelTarget = "https://xapp-d-sidecar.ricxapp.svc.cluster.local:4570/rmr"

func chain(c ...*x509.Certificate) []*x509.Certificate { return c }

// The tunnel carries RMR and HTTP alike, so these cases are what protects both.
func TestChannelCertificateBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-c", time.Hour)
	other := f.leaf("xapp-sidecar-e", time.Hour)
	bound := f.token(map[string]any{"x5t#S256": pki.ThumbprintS256(peer.Leaf)})

	cases := []struct {
		name     string
		req      ChannelRequest
		wantCode string
	}{
		{"token bound to the handshake certificate is accepted",
			ChannelRequest{Token: bound, PeerChain: chain(peer.Leaf), Target: channelTarget}, ""},
		{"token bound to another certificate is refused",
			ChannelRequest{Token: bound, PeerChain: chain(other.Leaf), Target: channelTarget}, ReasonX5tMismatch},
		{"no peer certificate at all is refused",
			ChannelRequest{Token: bound, Target: channelTarget}, ReasonClientCertMissing},
		{"an unbound bearer token is refused",
			ChannelRequest{Token: f.token(nil), PeerChain: chain(peer.Leaf), Target: channelTarget}, ReasonCnfMissing},
	}
	for _, tc := range cases {
		p, rej := f.v.AuthorizeChannel(context.Background(), tc.req)
		switch {
		case tc.wantCode == "" && rej != nil:
			t.Errorf("%s: rejected with %s (%s)", tc.name, rej.Code, rej.Detail)
		case tc.wantCode == "" && p.Binding != "x5t#S256":
			t.Errorf("%s: binding is %q", tc.name, p.Binding)
		case tc.wantCode != "" && (rej == nil || rej.Code != tc.wantCode):
			t.Errorf("%s: got %v, want %s", tc.name, rej, tc.wantCode)
		}
	}
}

func TestChannelProofBinding(t *testing.T) {
	f := newFixture(t)
	peer := f.leaf("xapp-sidecar-d", time.Hour)
	signer, err := jose.GenerateSigner("ES256")
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := signer.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	tok := f.token(map[string]any{"jkt": jkt})

	proof := func(target string, at time.Time) string {
		sum := jose.B64(sha256Sum(tok))
		p, err := signer.SignCompact(
			map[string]any{"typ": "dpop+jwt", "jwk": signer.PublicKey()},
			map[string]any{"jti": jose.B64([]byte(target + at.String())), "htm": ChannelOperation,
				"htu": target, "iat": at.Unix(), "ath": sum})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(channelTarget, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej != nil {
		t.Errorf("a valid channel proof was rejected: %s (%s)", rej.Code, rej.Detail)
	}

	// A proof minted for a different destination must not open this one.
	elsewhere := "https://xapp-x-sidecar.ricxapp.svc.cluster.local:4570/rmr"
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, Proof: proof(elsewhere, time.Now()), PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPHtuMismatch {
		t.Errorf("proof for another target: got %v, want %s", rej, ReasonDPoPHtuMismatch)
	}

	// The same proof twice is a replay.
	replayed := proof(channelTarget, time.Now())
	req := ChannelRequest{Token: tok, Proof: replayed, PeerChain: chain(peer.Leaf), Target: channelTarget}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej != nil {
		t.Fatalf("first use rejected: %s", rej.Code)
	}
	if _, rej := f.v.AuthorizeChannel(context.Background(), req); rej == nil || rej.Code != ReasonDPoPReplayed {
		t.Errorf("replayed proof: got %v, want %s", rej, ReasonDPoPReplayed)
	}

	// A jkt-bound token presented with no proof at all is refused.
	if _, rej := f.v.AuthorizeChannel(context.Background(), ChannelRequest{
		Token: tok, PeerChain: chain(peer.Leaf), Target: channelTarget,
	}); rej == nil || rej.Code != ReasonDPoPAsBearer {
		t.Errorf("proofless jkt token: got %v, want %s", rej, ReasonDPoPAsBearer)
	}
}

func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
XAPP_RESOURCE_CHANNEL_TEST_GO_EOF
```


## 6A.8 Check, build and test

```bash
cd ~/pqc-xapp-auth && for f in xapp-resource/config.go:72 xapp-resource/reasons.go:99 xapp-resource/replay.go:56 xapp-resource/introspect.go:52 xapp-resource/validator.go:445 xapp-resource/channel.go:89 xapp-resource/validator_test.go:179 xapp-resource/channel_test.go:112; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `xapp-resource/config.go` | 72 |
| `xapp-resource/reasons.go` | 99 |
| `xapp-resource/replay.go` | 56 |
| `xapp-resource/introspect.go` | 52 |
| `xapp-resource/validator.go` | 445 |
| `xapp-resource/channel.go` | 89 |
| `xapp-resource/validator_test.go` | 179 |
| `xapp-resource/channel_test.go` | 112 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && go vet ./xapp-resource/
```

```bash
cd ~/pqc-xapp-auth && go test -p=2 -count=1 -v ./xapp-resource/
```

Four test functions must pass: `TestValidator...`, plus
`TestChannelCertificateBinding` and `TestChannelProofBinding`.

Next: `chunk-06b-demo-xapp.md`.
