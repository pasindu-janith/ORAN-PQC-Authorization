# Chunk 3A - The CA service (code)

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** write the enrollment service and the SMO tool, compile them, and issue a real
bootstrap credential. Deployment is Chunk 3B.

**Needs the cluster?** No.

---

## This is one of the four files that carry the contribution

Read the `issue()` function in `ca/enroll/server.go` once, top to bottom. It is a list
of checks in a deliberate order:

1. **Authenticate against the right trust pool.** `/v1/enroll` accepts *only* SMO
   bootstrap certificates; `/v1/renew` accepts *only* current RIC operational
   certificates. Two endpoints, two credential classes, one code path.
2. **Identity comes from the certificate CN**, validated against a DNS-label pattern.
3. **Lifetime is clamped** to `[MIN, MAX]` and must not outlive the issuing CA. This is
   the only difference between Method A (168h) and Method B (15m).
4. **The CSR proves possession** (`csr.CheckSignature()`), and its *subject is ignored*
   - the CA sets the subject from the authenticated identity. A caller cannot ask to
   become another xApp.
5. **`branchFor(csr.PublicKey)` picks the issuing CA from the key type.** An ML-DSA key
   is signed by the ML-DSA CA, anything classical by the classical one. This single
   function is why one service serves both PKIs.
6. **Requested DNS names must be a subset** of those granted by the caller certificate.
7. **The bootstrap credential is consumed before signing** - written to disk and
   `fsync`-ed, then the certificate is issued. A crash mid-issue must not leave a
   reusable credential.

## 3A.1 The SMO onboarding library

```bash
cat > ~/pqc-xapp-auth/internal/smo/bootstrap.go <<'EOF'
// Package smo simulates the SMO onboarding step: issuing a one-time bootstrap
// certificate for an xApp. In a real deployment this happens outside the RIC.
package smo

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// Onboarding holds the SMO onboarding CA. KeyAlg selects the key type of the
// bootstrap credentials it issues: an ML-DSA onboarding CA must issue ML-DSA
// bootstrap keys, so that onboarding itself is post-quantum.
type Onboarding struct {
	cert   *x509.Certificate
	key    any
	org    string
	KeyAlg string
}

// LoadOnboarding reads the onboarding CA certificate and key.
func LoadOnboarding(certPath, keyPath, org string) (*Onboarding, error) {
	certs, err := pki.LoadCertsFile(certPath)
	if err != nil {
		return nil, err
	}
	key, err := pki.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, err
	}
	return &Onboarding{cert: certs[0], key: key, org: org, KeyAlg: "EC-P256"}, nil
}

// IssueBootstrap creates a fresh key and a bootstrap certificate for identity. The
// DNS names listed here are the only names the RIC CA will later put in the xApp's
// operational certificate.
func (o *Onboarding) IssueBootstrap(identity string, dnsNames []string, validity time.Duration) (*tls.Certificate, error) {
	alg := o.KeyAlg
	if alg == "" {
		alg = "EC-P256"
	}
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: identity, OrganizationalUnit: []string{"bootstrap"}, Organization: []string{o.org}},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.cert, key.Public(), o.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, o.cert.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// WriteCredential stores a certificate chain and key as tls.crt / tls.key in dir.
func WriteCredential(dir string, c *tls.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var chain []*x509.Certificate
	for _, der := range c.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		chain = append(chain, cert)
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(c.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), pki.EncodeCertsPEM(chain...), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}
EOF
```


## 3A.2 The one-time ledger

Keyed by **issuer + serial**. This is what makes onboarding single-use - the equivalent
of a DID wallet Secret being written once.

```bash
cat > ~/pqc-xapp-auth/ca/enroll/ledger.go <<'EOF'
package enroll

import (
	"bufio"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// UsedCredentials is an append-only ledger of consumed bootstrap certificates,
// keyed by issuer + serial, which makes every bootstrap credential single-use.
type UsedCredentials struct {
	mu   sync.Mutex
	path string
	used map[string]bool
}

// OpenUsedCredentials loads (or creates) the ledger in dir.
func OpenUsedCredentials(dir string) (*UsedCredentials, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	u := &UsedCredentials{path: filepath.Join(dir, "used-bootstrap-credentials.log"), used: map[string]bool{}}
	f, err := os.Open(u.path)
	if err != nil {
		if os.IsNotExist(err) {
			return u, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if key, _, ok := strings.Cut(sc.Text(), " "); ok {
			u.used[key] = true
		}
	}
	return u, sc.Err()
}

func credentialKey(c *x509.Certificate) string {
	return hex.EncodeToString(c.RawIssuer) + ":" + c.SerialNumber.Text(16)
}

// Consume marks the credential used, failing if it was already used. The entry is
// written to disk before the certificate is issued.
func (u *UsedCredentials) Consume(c *x509.Certificate) error {
	key := credentialKey(c)
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.used[key] {
		return fmt.Errorf("bootstrap certificate serial %s for %q has already been used", c.SerialNumber.Text(16), c.Subject.CommonName)
	}
	f, err := os.OpenFile(u.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s %s\n", key, c.Subject.CommonName, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	u.used[key] = true
	return nil
}
EOF
```


## 3A.3 The enrollment server

```bash
cat > ~/pqc-xapp-auth/ca/enroll/server.go <<'EOF'
// Package enroll implements the RIC intermediate CA enrollment service.
//
//	POST /v1/enroll?lifetime=<dur>  first enrollment, authenticated by a one-time SMO bootstrap certificate
//	POST /v1/renew?lifetime=<dur>   rotation/renewal, authenticated by a currently valid RIC operational certificate
//	GET  /v1/ca-chain               issuing chain (PEM)
//	GET  /healthz
//
// Both issuing endpoints share one code path; the leaf lifetime is a request
// parameter bounded by CA policy, which is what distinguishes Method A (long-term)
// from Method B (ephemeral) certificates.
package enroll

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// Config is read from the environment by ConfigFromEnv.
type Config struct {
	ListenAddr         string
	ServerCert         string // PEM chain presented by the service
	ServerKey          string
	IssuerCert         string // RIC intermediate CA certificate (classical branch)
	IssuerKey          string
	IssuerCertPQ       string // RIC intermediate CA certificate (ML-DSA branch, optional)
	IssuerKeyPQ        string
	BootstrapTrust     []string // SMO onboarding CAs: authenticate /v1/enroll
	OperationalTrust   []string // RIC intermediate CAs: authenticate /v1/renew
	StateDir           string
	Organization       string
	OrganizationalUnit string
	DefaultLifetime    time.Duration
	MinLifetime        time.Duration
	MaxLifetime        time.Duration
	AllowedDNSSuffixes []string
	Backdate           time.Duration
	PQKexOnly          bool // require the ML-KEM hybrid group for incoming TLS
}

// ConfigFromEnv loads the service configuration.
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		ListenAddr:         e.Str("LISTEN_ADDR", ":8443"),
		ServerCert:         e.Req("SERVER_CERT"),
		ServerKey:          e.Req("SERVER_KEY"),
		IssuerCert:         e.Req("ISSUER_CERT"),
		IssuerKey:          e.Req("ISSUER_KEY"),
		IssuerCertPQ:       e.Str("ISSUER_CERT_PQ", ""),
		IssuerKeyPQ:        e.Str("ISSUER_KEY_PQ", ""),
		BootstrapTrust:     e.List("BOOTSTRAP_TRUST_BUNDLE", nil),
		OperationalTrust:   e.List("OPERATIONAL_TRUST_BUNDLE", nil),
		StateDir:           e.Req("STATE_DIR"),
		Organization:       e.Req("ORG"),
		OrganizationalUnit: e.Req("XAPP_OU"),
		DefaultLifetime:    e.Dur("CA_DEFAULT_LEAF_LIFETIME", 24*time.Hour),
		MinLifetime:        e.Dur("CA_MIN_LEAF_LIFETIME", 5*time.Second),
		MaxLifetime:        e.Dur("CA_MAX_LEAF_LIFETIME", 30*24*time.Hour),
		AllowedDNSSuffixes: e.List("ALLOWED_DNS_SUFFIXES", nil),
		Backdate:           e.Dur("CA_BACKDATE", 2*time.Second),
		PQKexOnly:          e.Bool("PQ_KEX_ONLY", false),
	}
	if c.MinLifetime > c.MaxLifetime {
		e.Fail("CA_MIN_LEAF_LIFETIME must not exceed CA_MAX_LEAF_LIFETIME")
	}
	if len(c.BootstrapTrust) == 0 {
		e.Fail("BOOTSTRAP_TRUST_BUNDLE is required")
	}
	if len(c.OperationalTrust) == 0 {
		e.Fail("OPERATIONAL_TRUST_BUNDLE is required")
	}
	if (c.IssuerCertPQ == "") != (c.IssuerKeyPQ == "") {
		e.Fail("ISSUER_CERT_PQ and ISSUER_KEY_PQ must be set together")
	}
	return c, e.Err()
}

type profile string

const (
	profileBootstrap profile = "bootstrap"
	profileRenew     profile = "renew"
)

var identityPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// branch is one issuing CA: the classical one or the post-quantum (ML-DSA) one.
type branch struct {
	name string
	cert *x509.Certificate
	key  crypto.Signer
}

// Server issues xApp identity certificates. It holds one issuing branch per
// signature family; the key type of the CSR selects the branch, so the same
// enrollment, lifetime and rotation logic serves classical and ML-DSA identities.
type Server struct {
	cfg         Config
	classical   *branch
	postQuantum *branch
	bootPool    *x509.CertPool
	opPool      *x509.CertPool
	used        *UsedCredentials
	log         *slog.Logger
	now         func() time.Time
}

func loadBranch(name, certPath, keyPath string) (*branch, error) {
	certs, err := pki.LoadCertsFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("%s issuer certificate: %w", name, err)
	}
	key, err := pki.LoadPrivateKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%s issuer key: %w", name, err)
	}
	return &branch{name: name, cert: certs[0], key: key}, nil
}

// NewServer loads key material and the one-time-credential ledger.
func NewServer(cfg Config, log *slog.Logger) (*Server, error) {
	classical, err := loadBranch("classical", cfg.IssuerCert, cfg.IssuerKey)
	if err != nil {
		return nil, err
	}
	var postQuantum *branch
	if cfg.IssuerCertPQ != "" {
		if postQuantum, err = loadBranch("post-quantum", cfg.IssuerCertPQ, cfg.IssuerKeyPQ); err != nil {
			return nil, err
		}
	}
	bootPool, err := pki.LoadCertPool(cfg.BootstrapTrust...)
	if err != nil {
		return nil, fmt.Errorf("bootstrap trust: %w", err)
	}
	opPool, err := pki.LoadCertPool(cfg.OperationalTrust...)
	if err != nil {
		return nil, fmt.Errorf("operational trust: %w", err)
	}
	used, err := OpenUsedCredentials(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, classical: classical, postQuantum: postQuantum, bootPool: bootPool, opPool: opPool,
		used: used, log: log, now: time.Now}, nil
}

// branchFor selects the issuing CA from the public key in the CSR.
func (s *Server) branchFor(pub crypto.PublicKey) (*branch, error) {
	if pki.IsPostQuantum(pub) {
		if s.postQuantum == nil {
			return nil, fmt.Errorf("no post-quantum issuing branch configured (set ISSUER_CERT_PQ/ISSUER_KEY_PQ)")
		}
		return s.postQuantum, nil
	}
	return s.classical, nil
}

// TLSConfig requests (but does not verify at handshake) a client certificate; the
// handler verifies it against the pool that matches the endpoint.
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
	mux.HandleFunc("POST /v1/enroll", func(w http.ResponseWriter, r *http.Request) { s.issue(w, r, profileBootstrap) })
	mux.HandleFunc("POST /v1/renew", func(w http.ResponseWriter, r *http.Request) { s.issue(w, r, profileRenew) })
	mux.HandleFunc("GET /v1/ca-chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		certs := []*x509.Certificate{s.classical.cert}
		if s.postQuantum != nil {
			certs = append(certs, s.postQuantum.cert)
		}
		_, _ = w.Write(pki.EncodeCertsPEM(certs...))
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return mux
}

type rejection struct {
	status int
	code   string
	detail string
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request, p profile, rej rejection) {
	s.log.Warn("enrollment_rejected", "profile", p, "reason_code", rej.code, "reason", rej.detail, "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(rej.status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": rej.code, "reason": rej.detail})
}

func (s *Server) issue(w http.ResponseWriter, r *http.Request, p profile) {
	start := time.Now()
	now := s.now()

	// 1. Authenticate the caller with the credential class this endpoint accepts.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.reject(w, r, p, rejection{http.StatusUnauthorized, "client_certificate_missing", "no client certificate on the TLS session"})
		return
	}
	chain := r.TLS.PeerCertificates
	pool := s.opPool
	if p == profileBootstrap {
		pool = s.bootPool
	}
	if kind, err := pki.VerifyChain(chain, pool, now, x509.ExtKeyUsageClientAuth); err != nil {
		s.reject(w, r, p, rejection{http.StatusUnauthorized, "client_certificate_" + kind, fmt.Sprintf("%s credential rejected: %v", p, err)})
		return
	}
	caller := chain[0]
	identity := caller.Subject.CommonName
	if !identityPattern.MatchString(identity) {
		s.reject(w, r, p, rejection{http.StatusForbidden, "identity_invalid", fmt.Sprintf("CN %q is not a valid xApp identity", identity)})
		return
	}

	// 2. Lifetime policy.
	lifetime := s.cfg.DefaultLifetime
	if v := r.URL.Query().Get("lifetime"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_invalid", err.Error()})
			return
		}
		lifetime = d
	}
	if lifetime < s.cfg.MinLifetime || lifetime > s.cfg.MaxLifetime {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_out_of_policy",
			fmt.Sprintf("lifetime %s outside [%s, %s]", lifetime, s.cfg.MinLifetime, s.cfg.MaxLifetime)})
		return
	}
	notAfter := now.Add(lifetime)

	// 3. CSR: proof of possession and key policy. The subject is set by the CA from
	// the authenticated identity; the CSR subject is ignored.
	csr, rej := s.parseCSR(r)
	if rej != nil {
		s.reject(w, r, p, *rej)
		return
	}
	// The key type in the CSR selects the issuing CA: an ML-DSA key is signed by the
	// post-quantum branch, anything classical by the classical branch.
	br, err := s.branchFor(csr.PublicKey)
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "key_not_allowed", err.Error()})
		return
	}
	if notAfter.After(br.cert.NotAfter) {
		s.reject(w, r, p, rejection{http.StatusBadRequest, "lifetime_exceeds_issuer",
			fmt.Sprintf("requested lifetime outlives the %s issuing CA", br.name)})
		return
	}
	// DNS names must have been granted to the caller (bootstrap or current identity).
	for _, name := range csr.DNSNames {
		if !slices.Contains(caller.DNSNames, name) || !s.dnsSuffixAllowed(name) {
			s.reject(w, r, p, rejection{http.StatusForbidden, "dns_name_not_authorized",
				fmt.Sprintf("DNS name %q is not granted to identity %q", name, identity)})
			return
		}
	}

	// 4. One-time bootstrap: consume the credential before signing.
	if p == profileBootstrap {
		if err := s.used.Consume(caller); err != nil {
			s.reject(w, r, p, rejection{http.StatusForbidden, "bootstrap_credential_reused", err.Error()})
			return
		}
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusInternalServerError, "internal", err.Error()})
		return
	}
	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         identity,
			OrganizationalUnit: []string{s.cfg.OrganizationalUnit},
			Organization:       []string{s.cfg.Organization},
		},
		NotBefore:             now.Add(-s.cfg.Backdate),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		URIs:                  []*url.URL{{Scheme: "urn", Opaque: "oran:ric:xapp:" + identity}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, br.cert, csr.PublicKey, br.key)
	if err != nil {
		s.reject(w, r, p, rejection{http.StatusInternalServerError, "internal", err.Error()})
		return
	}
	leaf, _ := x509.ParseCertificate(der)

	s.log.Info("certificate_issued",
		"profile", p, "identity", identity, "serial", leaf.SerialNumber.Text(16),
		"issuer_branch", br.name, "key_alg", pki.KeyAlgName(csr.PublicKey), "sig_alg", leaf.SignatureAlgorithm.String(),
		"cert_bytes", len(leaf.Raw),
		"lifetime", lifetime.String(), "not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
		"x5t#S256", pki.ThumbprintS256(leaf), "authenticated_by_serial", caller.SerialNumber.Text(16),
		"elapsed_ms", float64(time.Since(start).Microseconds())/1000)

	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	_, _ = w.Write(pki.EncodeCertsPEM(leaf, br.cert))
}

func (s *Server) parseCSR(r *http.Request) (*x509.CertificateRequest, *rejection) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_unreadable", err.Error()}
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, &rejection{http.StatusBadRequest, "csr_malformed", "body is not a PEM CERTIFICATE REQUEST"}
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_malformed", err.Error()}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &rejection{http.StatusBadRequest, "csr_signature_invalid", "CSR proof of possession failed: " + err.Error()}
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return nil, &rejection{http.StatusBadRequest, "key_not_allowed", "EC keys must use P-256 or P-384"}
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, &rejection{http.StatusBadRequest, "key_not_allowed", "RSA keys must be at least 2048 bits"}
		}
	case ed25519.PublicKey:
	case *mldsa.PublicKey:
		// ML-DSA-44/65/87 (FIPS 204). All parameter sets are acceptable.
	default:
		return nil, &rejection{http.StatusBadRequest, "key_not_allowed", fmt.Sprintf("unsupported key type %T", k)}
	}
	return csr, nil
}

func (s *Server) dnsSuffixAllowed(name string) bool {
	if len(s.cfg.AllowedDNSSuffixes) == 0 {
		return true
	}
	for _, suffix := range s.cfg.AllowedDNSSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
EOF
```


## 3A.4 The two binaries

```bash
cat > ~/pqc-xapp-auth/ca/cmd/ric-ca/main.go <<'EOF'
// Command ric-ca runs the RIC intermediate CA enrollment service.
package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/ca/enroll"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/logx"
)

func main() {
	log := logx.New("ric-ca")
	cfg, err := enroll.ConfigFromEnv()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	srv, err := enroll.NewServer(cfg, log)
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
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()
	log.Info("listening", "addr", cfg.ListenAddr, "min_lifetime", cfg.MinLifetime.String(), "max_lifetime", cfg.MaxLifetime.String())
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
EOF
```


```bash
cat > ~/pqc-xapp-auth/ca/cmd/smo-sim/main.go <<'EOF'
// Command smo-sim issues one-time bootstrap credentials from the simulated SMO onboarding CA.
//
//	smo-sim -cn xapp-longterm -dns xapp-a.ricxapp.svc.cluster.local,xapp-a.ricxapp.svc -out out/bootstrap/xapp-a
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/smo"
)

func main() {
	cn := flag.String("cn", "", "xApp identity (certificate CN, must equal the Keycloak client id)")
	dns := flag.String("dns", "", "comma-separated DNS names granted to the xApp")
	out := flag.String("out", "", "output directory (tls.crt, tls.key)")
	caCert := flag.String("ca-cert", os.Getenv("SMO_ONBOARDING_CERT"), "onboarding CA certificate")
	caKey := flag.String("ca-key", os.Getenv("SMO_ONBOARDING_KEY"), "onboarding CA key")
	org := flag.String("org", os.Getenv("ORG"), "organization")
	validity := flag.Duration("validity", 24*time.Hour, "bootstrap certificate validity")
	keyAlg := flag.String("key-alg", "EC-P256", "bootstrap key algorithm (EC-P256, ML-DSA-44/65/87)")
	flag.Parse()
	if *cn == "" || *out == "" || *caCert == "" || *caKey == "" {
		flag.Usage()
		os.Exit(2)
	}
	ob, err := smo.LoadOnboarding(*caCert, *caKey, *org)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load onboarding CA:", err)
		os.Exit(1)
	}
	var names []string
	for _, n := range strings.Split(*dns, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	ob.KeyAlg = *keyAlg
	cred, err := ob.IssueBootstrap(*cn, names, *validity)
	if err != nil {
		fmt.Fprintln(os.Stderr, "issue:", err)
		os.Exit(1)
	}
	if err := smo.WriteCredential(*out, cred); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("bootstrap credential for %s (%s, serial %s, expires %s) written to %s\n",
		*cn, pki.KeyAlgName(cred.Leaf.PublicKey), cred.Leaf.SerialNumber.Text(16),
		cred.Leaf.NotAfter.UTC().Format(time.RFC3339), *out)
}
EOF
```


## 3A.5 Build and verify offline

```bash
cd ~/pqc-xapp-auth && for f in internal/smo/bootstrap.go:104 ca/enroll/ledger.go:72 ca/enroll/server.go:393 ca/cmd/ric-ca/main.go:53 ca/cmd/smo-sim/main.go:55; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `internal/smo/bootstrap.go` | 104 |
| `ca/enroll/ledger.go` | 72 |
| `ca/enroll/server.go` | 393 |
| `ca/cmd/ric-ca/main.go` | 53 |
| `ca/cmd/smo-sim/main.go` | 55 |


```bash
cd ~/pqc-xapp-auth && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./ca/cmd/ric-ca ./ca/cmd/smo-sim && ls -l out/bin/
```

Issue a real bootstrap credential - no cluster needed:

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; out/bin/smo-sim -cn xapp-longterm -dns xapp-a.ricxapp.svc.cluster.local,xapp-a.ricxapp.svc -validity 24h -org "$ORG" -out out/bootstrap/xapp-a -ca-cert out/pki/smo-onboarding-ca.crt -ca-key out/pki/smo-onboarding-ca.key
```

Inspect it - note `OU = bootstrap`, the granted DNS names, and `clientAuth` only:

```bash
cd ~/pqc-xapp-auth && openssl x509 -in out/bootstrap/xapp-a/tls.crt -noout -subject -issuer -ext subjectAltName,extendedKeyUsage -dates
```

Now the ML-DSA onboarding path - same tool, one flag:

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; out/bin/smo-sim -cn xapp-longterm -dns xapp-a.ricxapp.svc.cluster.local -validity 24h -org "$ORG" -key-alg ML-DSA-65 -out out/bootstrap/xapp-a-pq -ca-cert out/pki/smo-onboarding-ca-pq.crt -ca-key out/pki/smo-onboarding-ca-pq.key
```

The second must report `ML-DSA-65`. That the *same* 55-line tool issues both is the
point: the algorithm is a parameter, not a separate code path.

Next: `chunk-03b-ca-deploy.md`.
