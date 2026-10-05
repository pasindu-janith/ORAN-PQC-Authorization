# Chunk 7A - The post-quantum token shim

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


**Goal:** a service that takes a classical Keycloak token and re-issues it signed with
ML-DSA, bound to the client's post-quantum credential.

**Needs the cluster?** No.

---

## Why a shim exists at all

No released OAuth authorization server can sign an access token with ML-DSA. Keycloak
26.6 cannot; the Java platform only delivered ML-DSA in JDK 24 (JEP 497) and hybrid
TLS key exchange in JDK 27 (JEP 527), and Keycloak has not exposed either to token
signing. RFC 9964 defines how ML-DSA appears in JOSE - `kty: "AKP"`, a `pub` member,
`alg: ML-DSA-44/65/87` - but defining it is not the same as a server implementing it.

So the shim is the honest answer to "what would this look like if the authorization
server could do it". It is **not** a permanent component. `PQ_ISSUER=keycloak` points
every consumer straight at the authorization server with no code change, which is how
the shim leaves the deployment the day a server can sign this way. That exit condition
is the point of the design, and it is one variable.

## The security property that makes it safe

A re-signing service is a dangerous idea done carelessly: whoever can talk to it could
move a binding onto a credential they control. The shim refuses unless the caller
proves possession of **both** credentials in a single request:

- the **classical** one, by presenting the mTLS client certificate the incoming token
  is bound to (`cnf.x5t#S256`) or, for Method C, the DPoP proof key `cnf.jkt` names;
- the **post-quantum** one, by the `X-PQ-Proof` header - a JWS signed with the ML-DSA
  key, carrying the ML-DSA certificate chain in `x5c`.

If either alone sufficed, holding one credential would let an attacker transfer the
binding to the other. The shim also validates the incoming token with the **same**
`xapp-resource` validator the xApps use, so a token it will not accept as a resource
server it will not upgrade either.

Three further details to note while reading:

- **`upgraded_from`** records the original issuer, binding and `cnf`. The provenance of
  every post-quantum token is auditable back to the Keycloak token it came from.
- **The signing key is generated per pod.** `strategy: Recreate` plus 5-minute tokens
  makes that survivable, but it does mean a shim restart invalidates outstanding
  tokens. A production deployment would persist the key; say so rather than hide it.
- **`PQ_TOKEN_ISSUER`, not `PQ_ISSUER`.** The shim's own identity is deliberately a
  different variable from the client-side `shim|keycloak` selector. Using one name for
  both is a trap.

## 7A.1 The shim

```bash
cat > ~/pqc-xapp-auth/pqshim/shim.go <<'PQSHIM_SHIM_GO_EOF'
// Package pqshim implements the post-quantum token shim that sits beside Keycloak.
//
// Keycloak (Java 21) can neither sign tokens with ML-DSA nor terminate TLS with
// ML-DSA certificates or ML-KEM key exchange, so it remains the classical
// authorization server: it authenticates the xApp, applies the realm's
// authorization policy, and issues a classical, sender-constrained token.
//
// The shim upgrades that token:
//
//	POST /v1/upgrade   exchange a classical Keycloak token for an ML-DSA-signed token
//	                   bound to the caller's post-quantum credential
//	GET  /v1/jwks      the shim's AKP (ML-DSA) public keys
//
// The exchange is a *binding transfer* and requires proof of possession of both
// credentials in the same request:
//
//  1. the classical binding is proved exactly as at any resource server - the
//     embedded xappresource.Validator checks the Keycloak token and its
//     cnf.x5t#S256 against the mTLS peer certificate (Methods A/B), or its cnf.jkt
//     against a classical DPoP proof (Method C);
//  2. the post-quantum binding is proved by an ML-DSA-signed proof JWT carrying the
//     new credential: the PQ certificate chain in x5c (Methods A/B) or the AKP
//     public key in jwk (Method C), plus ath over the presented Keycloak token.
//
// Only then does the shim mint a token signed with ML-DSA whose cnf names the
// post-quantum credential. All signing and verification is done by jwx.
package pqshim

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pqbind"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

// ProofType and ProofHeader are shared with the client library.
const (
	ProofType   = pqbind.ProofType
	ProofHeader = pqbind.ProofHeader
)

// Config is read from the environment by ConfigFromEnv.
type Config struct {
	ListenAddr      string
	ServerCert      string
	ServerKey       string
	Issuer          string   // iss of the tokens this shim issues (PQ_TOKEN_ISSUER)
	SigningAlg      string   // ML-DSA-44 / ML-DSA-65 / ML-DSA-87
	PQTrustBundle   []string // trust anchors for the PQ certificate chains in x5c
	TokenLifetime   time.Duration
	ProofWindow     time.Duration
	ClockSkew       time.Duration
	ReplayCacheSize int
	PQKexOnly       bool
	// HealthAddr serves /healthz over plain HTTP for Kubernetes probes: the kubelet
	// predates ML-KEM and cannot complete a handshake on a PQ-only TLS port.
	HealthAddr string
}

// ConfigFromEnv loads the shim configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		ListenAddr:      e.Str("LISTEN_ADDR", ":8443"),
		ServerCert:      e.Req("SERVER_CERT"),
		ServerKey:       e.Req("SERVER_KEY"),
		Issuer:          e.Req("PQ_TOKEN_ISSUER"),
		SigningAlg:      e.Str("PQ_SIGNING_ALG", "ML-DSA-65"),
		PQTrustBundle:   e.List("PQ_TRUST_BUNDLE", nil),
		TokenLifetime:   e.Dur("PQ_TOKEN_LIFETIME", 5*time.Minute),
		ProofWindow:     e.Dur("DPOP_PROOF_WINDOW", 60*time.Second),
		ClockSkew:       e.Dur("CLOCK_SKEW", 30*time.Second),
		ReplayCacheSize: e.Int("DPOP_REPLAY_CACHE_SIZE", 100_000),
		PQKexOnly:       e.Bool("PQ_KEX_ONLY", false),
		HealthAddr:      e.Str("HEALTH_ADDR", ":8081"),
	}
	if len(c.PQTrustBundle) == 0 {
		e.Fail("PQ_TRUST_BUNDLE is required")
	}
	return c, e.Err()
}

// Server is the shim.
type Server struct {
	cfg       Config
	validator *xappresource.Validator // validates the incoming classical Keycloak token
	signer    jose.Signer             // ML-DSA signing key
	kid       string
	pqRoots   *x509.CertPool
	replay    *xappresource.ReplayCache
	log       *slog.Logger
	now       func() time.Time
}

// NewServer builds the shim. httpClient is used by the embedded validator to reach
// Keycloak (JWKS and introspection).
func NewServer(cfg Config, rcfg xappresource.Config, httpClient *http.Client, log *slog.Logger) (*Server, error) {
	validator, err := xappresource.NewValidator(rcfg, httpClient, log)
	if err != nil {
		return nil, fmt.Errorf("validator: %w", err)
	}
	signer, err := jose.GenerateSigner(cfg.SigningAlg)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	kid, err := signer.PublicJWK().Thumbprint()
	if err != nil {
		return nil, err
	}
	pqRoots, err := pki.LoadCertPool(cfg.PQTrustBundle...)
	if err != nil {
		return nil, fmt.Errorf("post-quantum trust bundle: %w", err)
	}
	return &Server{cfg: cfg, validator: validator, signer: signer, kid: kid, pqRoots: pqRoots,
		replay: xappresource.NewReplayCache(cfg.ReplayCacheSize), log: log, now: time.Now}, nil
}

// SigningAlg is the algorithm this shim signs with.
func (s *Server) SigningAlg() string { return s.signer.Alg() }

// KeyID is the kid of the shim's signing key.
func (s *Server) KeyID() string { return s.kid }

// TLSConfig serves the shim's (post-quantum) server certificate and requests the
// caller's classical client certificate, which the validator then checks.
func (s *Server) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.cfg.ServerCert, s.cfg.ServerKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientAuth:       tls.RequestClientCert,
		CurvePreferences: netx.CurvePreferences(s.cfg.PQKexOnly),
	}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/upgrade", s.handleUpgrade)
	mux.HandleFunc("GET /v1/jwks", s.handleJWKS)
	mux.HandleFunc("POST /v1/introspect", s.handleIntrospect)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return mux
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	key := jose.JWK{}
	for k, v := range s.signer.PublicJWK() {
		key[k] = v
	}
	key["kid"], key["use"] = s.kid, "sig"
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
}

// UpgradeResponse is the shim's answer.
type UpgradeResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	Alg         string         `json:"alg"`
	Cnf         map[string]any `json:"cnf"`
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, code, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	s.log.Warn("upgrade_rejected", "reason_code", code, "reason", detail, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "reason": detail})
}

func (s *Server) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Step 1: the classical token and its classical binding, checked exactly as a
	// resource server would check them.
	principal, rej := s.validator.Authorize(r, xappresource.ModeLocal)
	if rej != nil {
		s.fail(w, r, rej.Status, rej.Code, "%s", rej.Detail)
		return
	}
	classicalToken, err := bearerToken(r)
	if err != nil {
		s.fail(w, r, http.StatusUnauthorized, "authorization_malformed", "%v", err)
		return
	}

	// Step 2: possession of the post-quantum credential, and the binding it asks for.
	binding, proofInfo, rej2 := s.verifyPQProof(r, classicalToken, principal.ClientID)
	if rej2 != nil {
		s.fail(w, r, rej2.Status, rej2.Code, "%s", rej2.Detail)
		return
	}

	// Step 3: mint the ML-DSA-signed token.
	token, exp, err := s.issue(principal, binding)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "issue_failed", "%v", err)
		return
	}
	tokenType := "Bearer"
	if _, isDPoP := binding["jkt"]; isDPoP {
		tokenType = "DPoP"
	}
	s.log.Info("token_upgraded",
		"client_id", principal.ClientID,
		"classical_binding", principal.Binding, "classical_cnf", principal.Thumbprint,
		"pq_binding", proofInfo.bindingName, "pq_cnf", proofInfo.thumbprint,
		"pq_credential", proofInfo.credential, "proof_alg", proofInfo.alg,
		"signing_alg", s.signer.Alg(), "kid", s.kid,
		"classical_token_bytes", len(classicalToken), "pq_token_bytes", len(token),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(UpgradeResponse{
		AccessToken: token, TokenType: tokenType,
		ExpiresIn: int(time.Until(exp).Seconds()), Alg: s.signer.Alg(), Cnf: binding,
	})
}

func bearerToken(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", fmt.Errorf("expected exactly one Authorization header, got %d", len(values))
	}
	_, tok, ok := strings.Cut(strings.TrimSpace(values[0]), " ")
	if !ok || strings.TrimSpace(tok) == "" {
		return "", fmt.Errorf("Authorization header is not '<scheme> <token>'")
	}
	return strings.TrimSpace(tok), nil
}

type proofInfo struct {
	alg         string
	bindingName string
	thumbprint  string
	credential  string // certificate subject or JWK kind, for logging
}

// verifyPQProof checks the ML-DSA proof and returns the cnf it authorises.
func (s *Server) verifyPQProof(r *http.Request, classicalToken, clientID string) (map[string]any, proofInfo, *xappresource.Rejection) {
	var info proofInfo
	proofs := r.Header.Values(ProofHeader)
	if len(proofs) == 0 {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_missing", "no %s header", ProofHeader)
	}
	if len(proofs) > 1 {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_multiple", "more than one %s header", ProofHeader)
	}
	proof, err := jose.ParseCompact(proofs[0])
	if err != nil {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_malformed", "proof is not a compact JWS: %v", err)
	}
	if proof.Typ() != ProofType {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_wrong_typ", "proof typ is %q, expected %s", proof.Typ(), ProofType)
	}
	info.alg = proof.Alg()
	if !strings.HasPrefix(info.alg, "ML-DSA-") {
		return nil, info, reject(http.StatusBadRequest, "pq_proof_not_post_quantum",
			"proof alg %q is not an ML-DSA algorithm; the upgraded token would not be quantum-resistant", info.alg)
	}

	binding := map[string]any{}
	switch {
	case proof.Header["x5c"] != nil:
		// Methods A and B: the new binding is a post-quantum certificate.
		chain, rej := s.chainFromProof(proof)
		if rej != nil {
			return nil, info, rej
		}
		if kind, err := pki.VerifyChain(chain, s.pqRoots, s.now(), x509.ExtKeyUsageClientAuth); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_certificate_"+kind, "post-quantum certificate rejected: %v", err)
		}
		leaf := chain[0]
		if !pki.IsPostQuantum(leaf.PublicKey) {
			return nil, info, reject(http.StatusBadRequest, "pq_certificate_not_post_quantum",
				"certificate key is %s, not ML-DSA", pki.KeyAlgName(leaf.PublicKey))
		}
		// The post-quantum certificate must belong to the same xApp identity that
		// Keycloak authenticated, otherwise the binding could be moved to another xApp.
		if clientID != "" && leaf.Subject.CommonName != clientID {
			return nil, info, reject(http.StatusForbidden, "pq_identity_mismatch",
				"post-quantum certificate CN=%q does not match the authenticated client %q", leaf.Subject.CommonName, clientID)
		}
		if err := proof.VerifySignature(leaf.PublicKey); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_proof_signature_invalid",
				"proof is not signed by the certificate key: %v", err)
		}
		thumb := pki.ThumbprintS256(leaf)
		binding["x5t#S256"] = thumb
		info.bindingName, info.thumbprint = "x5t#S256", thumb
		info.credential = fmt.Sprintf("CN=%s %s", leaf.Subject.CommonName, pki.KeyAlgName(leaf.PublicKey))
	case proof.Header["jwk"] != nil:
		// Method C: the new binding is an ML-DSA DPoP key.
		rawJWK, ok := proof.Header["jwk"].(map[string]any)
		if !ok {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "jwk header is not an object")
		}
		key := jose.JWK(rawJWK)
		if key.Str("kty") != "AKP" {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_not_post_quantum",
				"proof key type is %q, expected AKP (RFC 9964)", key.Str("kty"))
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "proof jwk unusable: %v", err)
		}
		if err := proof.VerifySignature(pub); err != nil {
			return nil, info, reject(http.StatusUnauthorized, "pq_proof_signature_invalid", "proof signature invalid: %v", err)
		}
		thumb, err := key.Thumbprint()
		if err != nil {
			return nil, info, reject(http.StatusBadRequest, "pq_proof_jwk_invalid", "cannot compute JWK thumbprint: %v", err)
		}
		binding["jkt"] = thumb
		info.bindingName, info.thumbprint = "jkt", thumb
		info.credential = key.Str("alg") + " JWK"
	default:
		return nil, info, reject(http.StatusBadRequest, "pq_proof_no_credential",
			"proof carries neither x5c (certificate binding) nor jwk (DPoP binding)")
	}

	if rej := s.checkProofClaims(r, proof, classicalToken, info.thumbprint); rej != nil {
		return nil, info, rej
	}
	return binding, info, nil
}

func (s *Server) chainFromProof(proof *jose.JWS) ([]*x509.Certificate, *xappresource.Rejection) {
	raw, ok := proof.Header["x5c"].([]any)
	if !ok || len(raw) == 0 {
		return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c header is not a non-empty array")
	}
	var chain []*x509.Certificate
	for i, item := range raw {
		s64, ok := item.(string)
		if !ok {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(s64)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not base64 DER: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "pq_proof_x5c_invalid", "x5c[%d] is not a certificate: %v", i, err)
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// checkProofClaims verifies that the proof is bound to this token, this request and
// this moment, and that it has not been replayed.
func (s *Server) checkProofClaims(r *http.Request, proof *jose.JWS, classicalToken, thumbprint string) *xappresource.Rejection {
	claims, err := proof.Claims()
	if err != nil {
		return reject(http.StatusBadRequest, "pq_proof_malformed", "proof payload: %v", err)
	}
	ath, _ := claims["ath"].(string)
	sum := sha256.Sum256([]byte(classicalToken))
	want := jose.B64(sum[:])
	if ath == "" {
		return reject(http.StatusBadRequest, "pq_proof_ath_missing", "proof has no ath claim")
	}
	if subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
		return reject(http.StatusUnauthorized, "pq_proof_ath_mismatch",
			"proof ath %s is not the hash of the presented Keycloak token (%s)", ath, want)
	}
	if htm, _ := claims["htm"].(string); htm != r.Method {
		return reject(http.StatusBadRequest, "pq_proof_htm_mismatch", "proof htm %q does not match %q", htm, r.Method)
	}
	htuClaim, _ := claims["htu"].(string)
	got, errClaim := netx.NormalizeHTU(htuClaim)
	want2, errReq := netx.NormalizeHTU(s.cfg.Issuer + r.URL.EscapedPath())
	if errClaim != nil || errReq != nil || got != want2 {
		return reject(http.StatusBadRequest, "pq_proof_htu_mismatch", "proof htu %q does not match %q", htuClaim, want2)
	}
	iat, ok, err := numericClaim(claims, "iat")
	if err != nil || !ok {
		return reject(http.StatusBadRequest, "pq_proof_malformed", "proof has no numeric iat")
	}
	now, issued := s.now(), time.Unix(iat, 0)
	if issued.Before(now.Add(-s.cfg.ProofWindow-s.cfg.ClockSkew)) || issued.After(now.Add(s.cfg.ClockSkew)) {
		return reject(http.StatusBadRequest, "pq_proof_iat_out_of_window",
			"proof iat %s is outside the accepted window (%s)", issued.UTC().Format(time.RFC3339), s.cfg.ProofWindow)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return reject(http.StatusBadRequest, "pq_proof_jti_missing", "proof has no jti")
	}
	expiry := issued.Add(s.cfg.ProofWindow + 2*s.cfg.ClockSkew)
	switch s.replay.CheckAndStore(thumbprint+":"+jti, expiry, now) {
	case xappresource.ReplaySeen:
		return reject(http.StatusUnauthorized, "pq_proof_replayed", "proof jti %s has already been used", jti)
	case xappresource.ReplayFull:
		return reject(http.StatusServiceUnavailable, "pq_replay_cache_full", "replay cache is full")
	}
	return nil
}

// issue mints the ML-DSA-signed access token.
func (s *Server) issue(p *xappresource.Principal, binding map[string]any) (string, time.Time, error) {
	now := s.now()
	exp := now.Add(s.cfg.TokenLifetime)
	// Never outlive the Keycloak token the authorization decision came from.
	if kcExp, ok, _ := numericClaim(p.Claims, "exp"); ok {
		if t := time.Unix(kcExp, 0); t.Before(exp) {
			exp = t
		}
	}
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	claims := map[string]any{
		"iss": s.cfg.Issuer,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"jti": jose.B64(jti),
		"cnf": binding,
	}
	// Carry the authorization decision over unchanged.
	for _, name := range []string{"sub", "aud", "azp", "client_id", "scope", "realm_access", "resource_access"} {
		if v, ok := p.Claims[name]; ok {
			claims[name] = v
		}
	}
	// Provenance: which authorization server made the original decision.
	claims["upgraded_from"] = map[string]any{
		"iss":              p.Claims["iss"],
		"binding":          p.Binding,
		"cnf":              p.Thumbprint,
		"upgraded_at":      now.UTC().Format(time.RFC3339),
		"shim_signing_alg": s.signer.Alg(),
	}
	token, err := s.signer.SignCompact(map[string]any{"typ": "at+jwt", "kid": s.kid}, claims)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func reject(status int, code, format string, args ...any) *xappresource.Rejection {
	return &xappresource.Rejection{Status: status, Code: code, Detail: fmt.Sprintf(format, args...)}
}

func numericClaim(claims map[string]any, name string) (int64, bool, error) {
	raw, ok := claims[name]
	if !ok {
		return 0, false, nil
	}
	switch n := raw.(type) {
	case json.Number:
		v, err := n.Int64()
		return v, err == nil, err
	case float64:
		return int64(n), true, nil
	case int64:
		return n, true, nil
	}
	return 0, false, fmt.Errorf("claim %q is not numeric", name)
}

// handleIntrospect is the RFC 7662 endpoint for the tokens this shim issued, so a
// resource server can compare local validation against introspection in PQ mode
// exactly as it does with Keycloak in classical mode. The caller must present a
// certificate issued by one of the trusted RIC CAs.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	inactive := func() {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	}
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, "introspection_malformed", "%v", err)
		return
	}
	token := r.PostFormValue("token")
	if token == "" {
		s.fail(w, r, http.StatusBadRequest, "introspection_malformed", "no token parameter")
		return
	}
	parsed, err := jose.ParseCompact(token)
	if err != nil {
		inactive()
		return
	}
	if parsed.Kid() != s.kid {
		inactive()
		return
	}
	if err := parsed.VerifySignature(s.signer.PublicKey()); err != nil {
		s.log.Warn("introspection_signature_invalid", "error", err, "remote", r.RemoteAddr)
		inactive()
		return
	}
	claims, err := parsed.Claims()
	if err != nil {
		inactive()
		return
	}
	if exp, ok, _ := numericClaim(claims, "exp"); ok && s.now().After(time.Unix(exp, 0)) {
		inactive()
		return
	}
	out := map[string]any{"active": true}
	for k, v := range claims {
		out[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}
PQSHIM_SHIM_GO_EOF
```


## 7A.2 The binary

```bash
cat > ~/pqc-xapp-auth/pqshim/cmd/pq-shim/main.go <<'PQ_SHIM_MAIN_GO_EOF'
// Command pq-shim runs the post-quantum token shim (see package pqshim).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/logx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	"github.com/oran-ricsec/pqc-xapp-auth/pqshim"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

func main() {
	log := logx.New("pq-shim")
	cfg, err := pqshim.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	// The embedded validator checks the incoming classical Keycloak token, so it is
	// configured exactly like a resource server that trusts Keycloak.
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid validator configuration", "error", err)
		os.Exit(2)
	}
	e := &config.Env{}
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		log.Error("DIAL_OVERRIDES", "error", err)
		os.Exit(2)
	}
	// Client used to reach Keycloak (JWKS, introspection): classical trust anchors.
	roots, err := pki.LoadCertPool(rcfg.TrustBundle...)
	if err != nil {
		log.Error("trust bundle", "error", err)
		os.Exit(1)
	}
	httpClient := &http.Client{
		Transport: netx.NewTransport(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, overrides),
		Timeout:   20 * time.Second,
	}

	srv, err := pqshim.NewServer(cfg, rcfg, httpClient, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		os.Exit(1)
	}
	tlsConf, err := srv.TLSConfig()
	if err != nil {
		log.Error("server TLS", "error", err)
		os.Exit(1)
	}
	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    256 << 10, // ML-DSA proofs with an x5c chain are large headers
	}
	// Plain-HTTP health endpoint for Kubernetes probes (see Config.HealthAddr).
	if cfg.HealthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
		healthSrv := &http.Server{Addr: cfg.HealthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening",
		"addr", cfg.ListenAddr, "issuer", cfg.Issuer,
		"signing_alg", srv.SigningAlg(), "kid", srv.KeyID(),
		"upstream_issuer", rcfg.Issuer, "pq_kex_only", cfg.PQKexOnly)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
PQ_SHIM_MAIN_GO_EOF
```


## 7A.3 Check and build

```bash
cd ~/pqc-xapp-auth && for f in pqshim/shim.go:536 pqshim/cmd/pq-shim/main.go:98; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `pqshim/shim.go` | 536 |
| `pqshim/cmd/pq-shim/main.go` | 98 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && go vet ./pqshim/... && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./pqshim/cmd/pq-shim && ls -l out/bin/pq-shim
```

Next: `chunk-07b-shim-deploy.md`.
