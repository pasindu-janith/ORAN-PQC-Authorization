# Chunk 1 — The PKI

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** the certificate hierarchy everything else depends on, in both classical and
ML-DSA form, with the chains verified.

**Needs the cluster?** No — entirely offline, safe to run while the RIC is busy.

---

## What you are creating

```
SMO Root CA                     (simulated; its key never enters the cluster)
├── SMO Onboarding CA           issues ONE-TIME bootstrap certificates
│                               -> how an xApp proves it was onboarded
└── RIC Intermediate CA         issues the xApp's real operational identity
                                -> the only anchor Keycloak and the validator trust
```

Two CAs under one root is deliberate: a bootstrap credential is accepted *only* by the
enrollment endpoint, an operational certificate *only* by Keycloak and resource
servers. Neither can do the other's job.

Each branch is generated twice, classical (EC) and post-quantum (ML-DSA).

**Why a Go tool and not `openssl` for the ML-DSA branch:** OpenSSL 1.1.1 has no ML-DSA
algorithm support, so it cannot *create* those certificates or verify their signatures.
It can still parse the ASN.1 structure of one — see the check in 1.5, which is worth
understanding precisely.

## 1.1 OpenSSL extension profiles

`pathlen:0` on the intermediates means neither can issue another CA — only end-entity
certificates.

```bash
cat > ~/pqc-xapp-auth/ca/scripts/openssl.cnf <<'EOF'
# Extension profiles for the simulated SMO / RIC PKI (used by gen-pki.sh).
SAN = DNS:unused

[ req ]
distinguished_name = dn
prompt             = no

[ dn ]

[ v3_root ]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ v3_intermediate ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ v3_server ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = ${ENV::SAN}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF
```


## 1.2 The shared PKI library

Used by every component later: the CA, the client, the validator, the shim, the
sidecar. Three functions matter most:

- `ThumbprintS256` produces the `cnf.x5t#S256` value the whole project turns on.
- `GenerateKey` is the one place that knows both classical and ML-DSA algorithms.
- `VerifyChain` returns a *classified* failure (expired / untrusted / bad usage), so
  rejections downstream are specific rather than generic.

```bash
cat > ~/pqc-xapp-auth/internal/pki/pki.go <<'EOF'
// Package pki holds certificate helpers shared by the CA, the client library and
// the resource-side validator: PEM I/O, chain verification with classified failure
// reasons, and the RFC 8705 certificate thumbprint.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// ThumbprintS256 returns base64url(SHA-256(DER)) of a certificate: the value of
// the cnf "x5t#S256" member defined by RFC 8705 §3.1. It is independent of the
// certificate's signature algorithm.
func ThumbprintS256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseCertsPEM decodes every CERTIFICATE block in b.
func ParseCertsPEM(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return certs, nil
}

// EncodeCertsPEM encodes certificates as concatenated PEM blocks.
func EncodeCertsPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// LoadCertPool builds a pool from one or more PEM files.
func LoadCertPool(paths ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificates in %s", p)
		}
	}
	return pool, nil
}

// LoadCertsFile reads all certificates from a PEM file.
func LoadCertsFile(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertsPEM(b)
}

// ParsePrivateKeyPEM accepts PKCS#8, SEC1 (EC) and PKCS#1 (RSA) keys.
func ParsePrivateKeyPEM(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block in private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, err
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key is not a signer")
	}
	return s, nil
}

// LoadPrivateKeyFile reads a PEM private key.
func LoadPrivateKeyFile(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(b)
}

// EncodePrivateKeyPEM encodes a key as PKCS#8.
func EncodePrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// GenerateKey creates a fresh identity key. The algorithm is a parameter, so the
// same enrollment, rotation and binding code produces classical or post-quantum
// identities: ML-DSA keys come from crypto/mldsa (FIPS 204) in the standard library.
func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "", "EC-P256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "EC-P384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "Ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case "RSA-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "ML-DSA-44":
		return mldsa.GenerateKey(mldsa.MLDSA44())
	case "ML-DSA-65":
		return mldsa.GenerateKey(mldsa.MLDSA65())
	case "ML-DSA-87":
		return mldsa.GenerateKey(mldsa.MLDSA87())
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", alg)
	}
}

// IsPostQuantum reports whether a public key is a post-quantum (ML-DSA) key.
func IsPostQuantum(pub crypto.PublicKey) bool {
	_, ok := pub.(*mldsa.PublicKey)
	return ok
}

// KeyAlgName names a public key for logs and CLI output.
func KeyAlgName(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *mldsa.PublicKey:
		switch k.Parameters() {
		case mldsa.MLDSA44():
			return "ML-DSA-44"
		case mldsa.MLDSA65():
			return "ML-DSA-65"
		case mldsa.MLDSA87():
			return "ML-DSA-87"
		}
		return "ML-DSA"
	case *ecdsa.PublicKey:
		return "EC-" + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

// DescribeCert summarises a certificate for CLI output.
func DescribeCert(c *x509.Certificate) string {
	return fmt.Sprintf("CN=%s key=%s sig=%s serial=%s expires=%s (%d bytes)",
		c.Subject.CommonName, KeyAlgName(c.PublicKey), c.SignatureAlgorithm,
		c.SerialNumber.Text(16), c.NotAfter.UTC().Format(time.RFC3339), len(c.Raw))
}

// Chain verification failure classes, used to produce precise rejection reasons.
const (
	ChainExpired     = "expired"
	ChainNotYetValid = "not_yet_valid"
	ChainUntrusted   = "untrusted"
	ChainBadUsage    = "bad_usage"
	ChainInvalid     = "invalid"
)

// VerifyChain verifies chain[0] against roots using chain[1:] as intermediates at
// time now for the given extended key usage. On failure it returns a class and error.
func VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time, usage x509.ExtKeyUsage) (string, error) {
	if len(chain) == 0 {
		return ChainInvalid, errors.New("empty certificate chain")
	}
	leaf := chain[0]
	if now.After(leaf.NotAfter) {
		return ChainExpired, fmt.Errorf("certificate CN=%q serial=%s expired at %s (now %s)",
			leaf.Subject.CommonName, leaf.SerialNumber.Text(16),
			leaf.NotAfter.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return ChainNotYetValid, fmt.Errorf("certificate CN=%q not valid before %s",
			leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err == nil {
		return "", nil
	}
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case x509.Expired:
			return ChainExpired, err
		case x509.IncompatibleUsage:
			return ChainBadUsage, err
		}
		return ChainInvalid, err
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return ChainUntrusted, fmt.Errorf("certificate CN=%q is not issued by a trusted CA: %w", leaf.Subject.CommonName, err)
	}
	return ChainInvalid, err
}
EOF
```


## 1.3 The ML-DSA PKI generator

```bash
cat > ~/pqc-xapp-auth/ca/cmd/pki-gen/main.go <<'EOF'
// Command pki-gen generates the post-quantum branch of the testbed PKI with
// crypto/x509 and crypto/mldsa: a simulated SMO root, an SMO onboarding CA, the RIC
// intermediate CA and TLS server certificates, all signed with ML-DSA (FIPS 204).
//
// The classical branch is still generated by ca/scripts/gen-pki.sh with OpenSSL;
// OpenSSL 1.1.1 on the lab VM predates ML-DSA, which is why this tool exists.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

type serviceFlag []string

func (s *serviceFlag) String() string { return strings.Join(*s, ",") }
func (s *serviceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	out := flag.String("out", "out/pki", "output directory")
	org := flag.String("org", "O-RAN-RIC", "organization")
	clusterDomain := flag.String("cluster-domain", "cluster.local", "Kubernetes cluster domain")
	rootAlg := flag.String("root-alg", "ML-DSA-87", "root CA key algorithm")
	caAlg := flag.String("ca-alg", "ML-DSA-65", "intermediate CA key algorithm")
	serverAlg := flag.String("server-alg", "ML-DSA-65", "server certificate key algorithm")
	rootDays := flag.Int("root-days", 3650, "root CA validity in days")
	caDays := flag.Int("ca-days", 1825, "intermediate CA validity in days")
	serverDays := flag.Int("server-days", 365, "server certificate validity in days")
	var services serviceFlag
	flag.Var(&services, "service", "server certificate to issue, as name:namespace (repeatable)")
	flag.Parse()

	if err := run(*out, *org, *clusterDomain, *rootAlg, *caAlg, *serverAlg, *rootDays, *caDays, *serverDays, services); err != nil {
		fmt.Fprintln(os.Stderr, "pki-gen:", err)
		os.Exit(1)
	}
}

type issuer struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func run(out, org, clusterDomain, rootAlg, caAlg, serverAlg string, rootDays, caDays, serverDays int, services []string) error {
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(out, "ric-intermediate-ca-pq.crt")); err == nil {
		fmt.Printf("post-quantum PKI already present in %s (remove the files to regenerate)\n", out)
		return nil
	}

	root, err := selfSignedCA(out, "smo-root-ca-pq", rootAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"SMO"}, CommonName: "SMO Root CA PQ (simulated)"}, rootDays)
	if err != nil {
		return fmt.Errorf("root CA: %w", err)
	}
	onboarding, err := subCA(out, "smo-onboarding-ca-pq", caAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"SMO"}, CommonName: "SMO Onboarding CA PQ (simulated)"}, caDays, root)
	if err != nil {
		return fmt.Errorf("onboarding CA: %w", err)
	}
	intermediate, err := subCA(out, "ric-intermediate-ca-pq", caAlg,
		pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"Near-RT RIC"}, CommonName: "RIC Intermediate CA PQ"}, caDays, root)
	if err != nil {
		return fmt.Errorf("intermediate CA: %w", err)
	}
	_ = onboarding

	for _, svc := range services {
		name, ns, ok := strings.Cut(svc, ":")
		if !ok {
			return fmt.Errorf("-service %q is not name:namespace", svc)
		}
		dns := []string{
			fmt.Sprintf("%s.%s.svc.%s", name, ns, clusterDomain),
			fmt.Sprintf("%s.%s.svc", name, ns),
			fmt.Sprintf("%s.%s", name, ns),
			name, "localhost",
		}
		if err := serverCert(out, name+"-server-pq", serverAlg,
			pkix.Name{Organization: []string{org}, OrganizationalUnit: []string{"Near-RT RIC"}, CommonName: dns[0]},
			dns, serverDays, intermediate); err != nil {
			return fmt.Errorf("%s server certificate: %w", name, err)
		}
	}

	// Trust bundle: the RIC intermediate is the anchor relying parties are configured with.
	bundle := append(pki.EncodeCertsPEM(intermediate.cert), pki.EncodeCertsPEM(root.cert)...)
	if err := os.WriteFile(filepath.Join(out, "ric-ca-bundle-pq.crt"), bundle, 0o644); err != nil {
		return err
	}
	fmt.Printf("post-quantum PKI written to %s (root %s, CAs %s, servers %s)\n", out, rootAlg, caAlg, serverAlg)
	return nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func write(out, name string, cert *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) error {
	if err := os.WriteFile(filepath.Join(out, name+".crt"), pki.EncodeCertsPEM(cert), 0o644); err != nil {
		return err
	}
	keyPEM, err := pki.EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	if len(chain) > 0 {
		full := append(pki.EncodeCertsPEM(cert), pki.EncodeCertsPEM(chain...)...)
		if err := os.WriteFile(filepath.Join(out, name+"-chain.crt"), full, 0o644); err != nil {
			return err
		}
	}
	fmt.Println("  ", name+":", pki.DescribeCert(cert))
	return nil
}

func selfSignedCA(out, name, alg string, subject pkix.Name, days int) (*issuer, error) {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuer{cert: cert, key: key}, write(out, name, cert, key)
}

func subCA(out, name, alg string, subject pkix.Name, days int, parent *issuer) (*issuer, error) {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), parent.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &issuer{cert: cert, key: key}, write(out, name, cert, key, parent.cert)
}

func serverCert(out, name, alg string, subject pkix.Name, dnsNames []string, days int, parent *issuer) error {
	key, err := pki.GenerateKey(alg)
	if err != nil {
		return err
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, key.Public(), parent.key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	return write(out, name, cert, key, parent.cert)
}
EOF
```


## 1.4 The generator script

Runs the classical branch with OpenSSL, then calls the Go tool for the ML-DSA branch.
Both halves are idempotent — re-running will not overwrite an existing PKI.

```bash
cat > ~/pqc-xapp-auth/ca/scripts/gen-pki.sh <<'EOF'
#!/usr/bin/env bash
# Generates the PKI:
#   smo-root-ca          simulated SMO root CA (offline: its key never enters the cluster)
#   smo-onboarding-ca    simulated SMO onboarding CA, issues one-time bootstrap certificates
#   ric-intermediate-ca  RIC intermediate CA, issues xApp operational identity certificates
#   keycloak-server      TLS server certificate for Keycloak
#   ric-ca-server        TLS server certificate for the enrollment service
# then the ML-DSA branch via pki-gen. Configuration comes from config/env.sh.
set -euo pipefail

OUT=${1:?usage: gen-pki.sh <out-dir>}
: "${ORG:?}" "${RICSEC_NAMESPACE:?}" "${CLUSTER_DOMAIN:?}" "${KEYCLOAK_SERVICE:?}" "${RIC_CA_SERVICE:?}"
: "${KEYCLOAK_NAMESPACE:=$RICSEC_NAMESPACE}"
: "${ROOT_CA_DAYS:=3650}" "${INTERMEDIATE_CA_DAYS:=1825}" "${SERVER_CERT_DAYS:=365}"

HERE=$(cd "$(dirname "$0")" && pwd)
CNF="$HERE/openssl.cnf"
mkdir -p "$OUT"

generate_classical=1
if [[ -f "$OUT/ric-intermediate-ca.crt" ]]; then
  echo "classical PKI already present in $OUT (remove the directory to regenerate)"
  generate_classical=0
fi

if [[ $generate_classical == 1 ]]; then

newkey() { # newkey <file> <curve>
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:"$2" -out "$1"
  chmod 600 "$1"
}

sign() { # sign <name> <subject> <extension-section> <days> <issuer-name> <curve>
  local name=$1 subj=$2 ext=$3 days=$4 issuer=$5 curve=$6
  newkey "$OUT/$name.key" "$curve"
  openssl req -new -key "$OUT/$name.key" -subj "$subj" -config "$CNF" -out "$OUT/$name.csr"
  openssl x509 -req -in "$OUT/$name.csr" -CA "$OUT/$issuer.crt" -CAkey "$OUT/$issuer.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days "$days" -sha384 \
    -extfile "$CNF" -extensions "$ext" -out "$OUT/$name.crt"
  rm -f "$OUT/$name.csr"
}

export SAN="DNS:unused"

echo "==> SMO root CA (simulated)"
newkey "$OUT/smo-root-ca.key" P-384
openssl req -x509 -new -key "$OUT/smo-root-ca.key" -sha384 -days "$ROOT_CA_DAYS" \
  -subj "/O=${ORG}/OU=SMO/CN=SMO Root CA (simulated)" \
  -config "$CNF" -extensions v3_root -out "$OUT/smo-root-ca.crt"

echo "==> SMO onboarding CA (bootstrap credentials)"
sign smo-onboarding-ca "/O=${ORG}/OU=SMO/CN=SMO Onboarding CA (simulated)" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

echo "==> RIC intermediate CA"
sign ric-intermediate-ca "/O=${ORG}/OU=Near-RT RIC/CN=RIC Intermediate CA" v3_intermediate "$INTERMEDIATE_CA_DAYS" smo-root-ca P-384

svc_sans() { # svc_sans <service> <namespace>
  local s=$1 ns=$2
  echo "DNS:${s}.${ns}.svc.${CLUSTER_DOMAIN},DNS:${s}.${ns}.svc,DNS:${s}.${ns}"
}

echo "==> Keycloak server certificate"
# Valid for BOTH candidate deployments, so the Chunk 4 decision (reuse the existing
# Keycloak, or run a dedicated one in ricsec) needs no PKI regeneration.
SAN="$(svc_sans "$KEYCLOAK_SERVICE" "$RICSEC_NAMESPACE"),$(svc_sans "$KEYCLOAK_SERVICE" "$KEYCLOAK_NAMESPACE"),DNS:${KEYCLOAK_SERVICE},DNS:localhost,IP:127.0.0.1"
export SAN
sign keycloak-server "/O=${ORG}/OU=XRF/CN=${KEYCLOAK_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

echo "==> RIC CA enrollment service server certificate"
SAN="$(svc_sans "$RIC_CA_SERVICE" "$RICSEC_NAMESPACE"),DNS:${RIC_CA_SERVICE},DNS:localhost,IP:127.0.0.1"
sign ric-ca-server "/O=${ORG}/OU=RIC CA/CN=${RIC_CA_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}" v3_server "$SERVER_CERT_DAYS" ric-intermediate-ca P-256

# Chains: servers present leaf+intermediate; relying parties trust the RIC intermediate.
cat "$OUT/keycloak-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/keycloak-server-chain.crt"
cat "$OUT/ric-ca-server.crt" "$OUT/ric-intermediate-ca.crt" > "$OUT/ric-ca-server-chain.crt"
cat "$OUT/ric-intermediate-ca.crt" "$OUT/smo-root-ca.crt" > "$OUT/ric-ca-bundle.crt"
rm -f "$OUT"/*.srl

echo "==> Verifying chains"
openssl verify -CAfile "$OUT/smo-root-ca.crt" "$OUT/ric-intermediate-ca.crt" "$OUT/smo-onboarding-ca.crt"
openssl verify -CAfile "$OUT/smo-root-ca.crt" -untrusted "$OUT/ric-intermediate-ca.crt" "$OUT/keycloak-server.crt" "$OUT/ric-ca-server.crt"
fi

# Post-quantum branch: ML-DSA root, onboarding CA, RIC intermediate CA and server
# certificates. OpenSSL 1.1.1 has no ML-DSA algorithm support, so crypto/x509 does it.
echo "==> Post-quantum branch (ML-DSA, crypto/x509)"
"${PKI_GEN:-out/bin/pki-gen}" -out "$OUT" -org "$ORG" -cluster-domain "$CLUSTER_DOMAIN" \
  -root-alg "${PQ_ROOT_ALG:-ML-DSA-87}" -ca-alg "${PQ_CA_ALG:-ML-DSA-65}" -server-alg "${PQ_SERVER_ALG:-ML-DSA-65}" \
  -service "${RIC_CA_SERVICE}:${RICSEC_NAMESPACE}" -service "${PQ_SHIM_SERVICE:-pq-shim}:${RICSEC_NAMESPACE}"
EOF
```


```bash
chmod +x ~/pqc-xapp-auth/ca/scripts/gen-pki.sh
```

## 1.5 Build, run and verify

```bash
cd ~/pqc-xapp-auth && for f in ca/scripts/openssl.cnf:27 internal/pki/pki.go:249 ca/cmd/pki-gen/main.go:216 ca/scripts/gen-pki.sh:89; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `ca/scripts/openssl.cnf` | 27 |
| `internal/pki/pki.go` | 249 |
| `ca/cmd/pki-gen/main.go` | 216 |
| `ca/scripts/gen-pki.sh` | 89 |


```bash
cd ~/pqc-xapp-auth && CGO_ENABLED=0 go build -p=2 -o out/bin/pki-gen ./ca/cmd/pki-gen
```

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; PKI_GEN=$PWD/out/bin/pki-gen ca/scripts/gen-pki.sh out/pki
```

The script verifies the classical chains itself (`openssl verify` must print `OK`), and
prints a description of each ML-DSA certificate as it writes it.

```bash
ls ~/pqc-xapp-auth/out/pki/
```

```bash
cd ~/pqc-xapp-auth && openssl x509 -in out/pki/ric-intermediate-ca.crt -noout -subject -issuer && openssl x509 -in out/pki/ric-ca-server.crt -noout -subject -ext subjectAltName
```

### What OpenSSL can and cannot do with the ML-DSA certificates

> **Correction applied.** An earlier version of this step said OpenSSL "cannot read"
> these files. That is wrong, and your own output disproves it. An X.509 certificate
> is ASN.1, so OpenSSL parses the structure and prints the subject perfectly well.
> What it cannot do is understand the ML-DSA algorithm OID — so it cannot interpret
> the public key or verify the signature — and it cannot create one. **That last point
> is the actual reason `pki-gen` exists.**

```bash
cd ~/pqc-xapp-auth && echo "--- subject parses fine ---"; openssl x509 -in out/pki/ric-intermediate-ca-pq.crt -noout -subject; echo "--- but the signature cannot be verified ---"; openssl verify -CAfile out/pki/smo-root-ca-pq.crt out/pki/ric-intermediate-ca-pq.crt; echo "--- and the key algorithm is unknown ---"; openssl x509 -in out/pki/ric-intermediate-ca-pq.crt -noout -text 2>&1 | grep -A2 'Public Key Algorithm'
```

### Record the size difference

Real measurement data for your write-up:

```bash
cd ~/pqc-xapp-auth && ls -l out/pki/ric-intermediate-ca.crt out/pki/ric-intermediate-ca-pq.crt
```

| | DER | PEM file |
|---|---|---|
| Classical intermediate CA (EC P-384) | ~600 B | ~818 B |
| ML-DSA-65 intermediate CA | 6,949 B | ~9,467 B |

**About 11x larger**, and that propagates into every certificate chain on the wire.

Next: `chunk-02-shared-libraries.md`.
