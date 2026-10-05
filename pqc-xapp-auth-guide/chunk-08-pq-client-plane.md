# Chunk 8 - The post-quantum client plane

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


**Goal:** one command per method that walks the whole flow and prints it, then the
switch that makes the deployment post-quantum, then all three methods passing against
it.

**Needs the cluster?** Yes.

---

## What changes, and what does not

The client library has been post-quantum aware since Chunk 5. Nothing in it changes
here. What changes is three variables and four Kubernetes objects:

| | classical | post-quantum |
|---|---|---|
| Token the validators trust | Keycloak, RS256 | pq-shim, ML-DSA-65 |
| RIC CA server certificate | `ric-ca-server` (ECDSA) | `ric-ca-server-pq` (ML-DSA-65) |
| xApp identity | ECDSA P-256 | **both** - ECDSA *and* ML-DSA-65 |
| TLS key exchange | X25519 | X25519MLKEM768, required |

That table is the answer to "what did the migration cost": one flag, a re-rendered
ConfigMap, and a different server certificate. No forked code path.

## 8A.1 The walkthrough CLI

`methodrun` prints every step of one method: onboarding, enrollment, token issuance,
the shim upgrade with its size delta, the negotiated TLS group, both validation
modes, the method-specific behaviour (rotation for B, proof replay for C), and the
negative test that proves the token alone is not enough.

```bash
cat > ~/pqc-xapp-auth/cmd/methodrun/main.go <<'METHODRUN_MAIN_GO_EOF'
// Command methodrun walks one binding method end to end and prints every step, so a
// single command shows the whole flow on the CLI: onboarding, enrollment, token
// issuance, the post-quantum upgrade, the negotiated TLS key exchange, resource calls
// under both validation modes, and the negative test that proves the binding is
// enforced.
//
//	methodrun -method A            classical run
//	methodrun -method A -pq        post-quantum run (ML-DSA tokens, ML-KEM key exchange)
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/jose"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/logx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/smo"
	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

var (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	red    = "\033[31m"
	cyan   = "\033[36m"
	yellow = "\033[33m"
	reset  = "\033[0m"
)

func init() {
	if os.Getenv("NO_COLOR") != "" {
		bold, dim, green, red, cyan, yellow, reset = "", "", "", "", "", "", ""
	}
}

var stepNo int

func step(format string, args ...any) {
	stepNo++
	fmt.Printf("\n%s%s[%d] %s%s\n", bold, cyan, stepNo, fmt.Sprintf(format, args...), reset)
}

func item(label string, format string, args ...any) {
	fmt.Printf("    %-26s %s\n", label+":", fmt.Sprintf(format, args...))
}

func ok(format string, args ...any) {
	fmt.Printf("    %sOK%s  %s\n", green, reset, fmt.Sprintf(format, args...))
}
func warn(format string, args ...any) {
	fmt.Printf("    %s!%s   %s\n", yellow, reset, fmt.Sprintf(format, args...))
}
func fail(format string, args ...any) {
	fmt.Printf("    %sFAIL%s %s\n", red, reset, fmt.Sprintf(format, args...))
}

type runner struct {
	ctx        context.Context
	log        *slog.Logger
	cfg        xappclient.Config
	onboarding *smo.Onboarding
	pqOnboard  *smo.Onboarding
	roots      *x509.CertPool
	overrides  map[string]string
	resource   string
	pq         bool
	failures   int
}

func main() {
	method := flag.String("method", "A", "binding method: A, B or C")
	pq := flag.Bool("pq", false, "run in post-quantum mode (ML-DSA tokens and certificates, ML-KEM key exchange)")
	flag.Parse()

	m := xappclient.Method(strings.ToUpper(*method))
	r, err := newRunner(m, *pq)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration:", err)
		os.Exit(2)
	}
	if err := r.run(m); err != nil {
		fail("%v", err)
		os.Exit(1)
	}
	fmt.Println()
	if r.failures > 0 {
		fmt.Printf("%s%d check(s) failed%s\n", red, r.failures, reset)
		os.Exit(1)
	}
	fmt.Printf("%s%sAll checks passed.%s\n", bold, green, reset)
}

func newRunner(m xappclient.Method, pq bool) (*runner, error) {
	e := &config.Env{}
	r := &runner{ctx: context.Background(), log: logx.New("methodrun"), pq: pq}
	r.resource = strings.TrimRight(e.Req("RESOURCE_URL"), "/")
	clientID := map[xappclient.Method]string{
		xappclient.MethodLongTerm:  e.Req("LONGTERM_CLIENT_ID"),
		xappclient.MethodEphemeral: e.Req("EPHEMERAL_CLIENT_ID"),
		xappclient.MethodDPoP:      e.Req("DPOP_CLIENT_ID"),
	}[m]
	lifetime := e.Dur("LONGTERM_CERT_LIFETIME", 168*time.Hour)
	if m == xappclient.MethodEphemeral {
		lifetime = e.Dur("EPHEMERAL_CERT_LIFETIME", 15*time.Minute)
	}
	r.cfg = xappclient.Config{
		Method: m, ClientID: clientID,
		TokenURL:         e.Req("KEYCLOAK_TOKEN_URL"),
		Scope:            e.Str("TOKEN_SCOPE", ""),
		TrustBundle:      e.List("RIC_TRUST_BUNDLE", nil),
		CAURL:            e.Req("RIC_CA_URL"),
		KeyAlg:           e.Str("IDENTITY_KEY_ALG", "EC-P256"),
		CertLifetime:     lifetime,
		Rotation:         xappclient.RotateOnCertExpiry,
		DPoPAlg:          e.Str("DPOP_ALG", "ES256"),
		PQEnabled:        pq,
		PQIssuer:         xappclient.PQIssuer(e.Str("PQ_ISSUER", string(xappclient.PQIssuerShim))),
		PQShimURL:        e.Str("PQ_SHIM_URL", ""),
		PQKeyAlg:         e.Str("PQ_IDENTITY_KEY_ALG", "ML-DSA-65"),
		PQDPoPAlg:        e.Str("PQ_DPOP_ALG", "ML-DSA-44"),
		PQKexOnly:        e.Bool("PQ_KEX_ONLY", true),
		PQUpgradeTimeout: 60 * time.Second,
		HTTPTimeout:      30 * time.Second,
	}
	onbCert, onbKey, org := e.Req("SMO_ONBOARDING_CERT"), e.Req("SMO_ONBOARDING_KEY"), e.Req("ORG")
	pqOnbCert := e.Str("SMO_ONBOARDING_CERT_PQ", "")
	pqOnbKey := e.Str("SMO_ONBOARDING_KEY_PQ", "")
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return nil, err
	}
	r.overrides, r.cfg.DialOverrides = overrides, overrides
	if r.roots, err = pki.LoadCertPool(r.cfg.TrustBundle...); err != nil {
		return nil, err
	}
	if r.onboarding, err = smo.LoadOnboarding(onbCert, onbKey, org); err != nil {
		return nil, err
	}
	if pq {
		if pqOnbCert == "" || pqOnbKey == "" {
			return nil, fmt.Errorf("SMO_ONBOARDING_CERT_PQ/KEY_PQ are required in post-quantum mode")
		}
		if r.pqOnboard, err = smo.LoadOnboarding(pqOnbCert, pqOnbKey, org); err != nil {
			return nil, err
		}
		r.pqOnboard.KeyAlg = r.cfg.PQKeyAlg
	}
	return r, nil
}

// newClient onboards a fresh identity and starts a client.
func (r *runner) newClient() (xappclient.Client, error) {
	cfg := r.cfg
	boot, err := r.onboarding.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = boot
	if r.pq {
		pqBoot, err := r.pqOnboard.IssueBootstrap(cfg.ClientID, nil, 10*time.Minute)
		if err != nil {
			return nil, err
		}
		cfg.PQBootstrap = pqBoot
	}
	c, err := xappclient.New(cfg, r.log)
	if err != nil {
		return nil, err
	}
	return c, c.Start(r.ctx)
}

func (r *runner) path(mode xappresource.Mode) string {
	if mode == xappresource.ModeIntrospection {
		return r.resource + "/api/v1/introspect/sdl/demo"
	}
	return r.resource + "/api/v1/sdl/demo"
}

func (r *runner) check(cond bool, format string, args ...any) {
	if cond {
		ok(format, args...)
		return
	}
	r.failures++
	fail(format, args...)
}

func (r *runner) run(m xappclient.Method) error {
	mode := "classical"
	if r.pq {
		mode = "post-quantum"
	}
	fmt.Printf("%s%sMethod %s walkthrough (%s)%s\n", bold, cyan, m, mode, reset)

	step("Configuration")
	item("method", "%s (%s)", m, methodDescription(m))
	item("keycloak client", "%s", r.cfg.ClientID)
	item("identity key", "%s", r.cfg.KeyAlg)
	item("certificate lifetime", "%s", r.cfg.CertLifetime)
	if m == xappclient.MethodDPoP {
		item("DPoP proof key", "%s", r.cfg.DPoPAlg)
	}
	if r.pq {
		item("post-quantum identity", "%s", r.cfg.PQKeyAlg)
		if m == xappclient.MethodDPoP {
			item("post-quantum DPoP key", "%s", r.cfg.PQDPoPAlg)
		}
		if r.cfg.PQIssuer == xappclient.PQIssuerKeycloak {
			item("post-quantum token issuer", "the authorization server itself (no shim in the path)")
		} else {
			item("post-quantum token issuer", "pq-shim at %s", r.cfg.PQShimURL)
		}
		item("TLS key exchange", "X25519MLKEM768 required: %v", r.cfg.PQKexOnly)
	}
	item("resource xApp", "%s", r.resource)

	step("SMO onboarding and enrollment with the RIC CA")
	start := time.Now()
	client, err := r.newClient()
	if err != nil {
		return fmt.Errorf("enrollment: %w", err)
	}
	enrollMS := float64(time.Since(start).Microseconds()) / 1000
	d := client.Describe()
	item("classical certificate", "%s", d.ClassicalCert)
	if r.pq {
		item("post-quantum certificate", "%s", d.PQCert)
		r.check(strings.HasPrefix(d.PQAlg, "ML-DSA"), "identity certificate uses %s", d.PQAlg)
	}
	item("enrollment time", "%.1f ms", enrollMS)

	step("Access token")
	start = time.Now()
	tok, err := client.Token(r.ctx)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}
	tokenMS := float64(time.Since(start).Microseconds()) / 1000
	if tok.Classical != nil {
		item("Keycloak token", "alg=%s binding=cnf.%s bytes=%d", tok.Classical.Alg, tok.Classical.Binding, len(tok.Classical.Value))
		item("upgraded token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
		item("size change", "%+d bytes (%.1fx)", len(tok.Value)-len(tok.Classical.Value),
			float64(len(tok.Value))/float64(len(tok.Classical.Value)))
		r.check(strings.HasPrefix(tok.Alg, "ML-DSA"), "token is signed with %s", tok.Alg)
	} else {
		item("token", "alg=%s binding=cnf.%s bytes=%d", tok.Alg, tok.Binding, len(tok.Value))
	}
	item("cnf value", "%s", tok.Thumbprint)
	item("expires", "%s (in %s)", tok.ExpiresAt.UTC().Format(time.RFC3339), time.Until(tok.ExpiresAt).Round(time.Second))
	item("issue time", "%.1f ms", tokenMS)
	printClaims(tok)

	step("Resource request with local validation")
	status, body, state, err := r.call(client, r.path(xappresource.ModeLocal))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))
	if state != nil {
		item("TLS key exchange", "%s", state.CurveID)
		item("TLS version", "0x%x", state.Version)
		if len(state.PeerCertificates) > 0 {
			item("server certificate", "%s", pki.KeyAlgName(state.PeerCertificates[0].PublicKey))
		}
		if r.pq {
			r.check(netx.IsPQKex(state.CurveID), "key exchange is post-quantum (%s)", state.CurveID)
		}
	}

	step("Resource request validated by introspection")
	status, body, _, err = r.call(client, r.path(xappresource.ModeIntrospection))
	if err != nil {
		return err
	}
	r.check(status == http.StatusOK, "HTTP %d %s", status, strings.TrimSpace(body))

	if err := r.methodSpecific(m, client, tok); err != nil {
		return err
	}
	return r.negative(m, client, tok)
}

func methodDescription(m xappclient.Method) string {
	switch m {
	case xappclient.MethodLongTerm:
		return "RFC 8705 certificate-bound, long-term identity key"
	case xappclient.MethodEphemeral:
		return "RFC 8705 certificate-bound, ephemeral identity key"
	case xappclient.MethodDPoP:
		return "RFC 9449 DPoP"
	}
	return string(m)
}

func printClaims(tok *xappclient.Token) {
	interesting := []string{"iss", "aud", "azp", "scope", "realm_access"}
	parts := make([]string, 0, len(interesting))
	for _, name := range interesting {
		if v, ok := tok.Claims[name]; ok {
			raw, _ := json.Marshal(v)
			parts = append(parts, fmt.Sprintf("%s=%s", name, raw))
		}
	}
	item("claims", "%s", strings.Join(parts, " "))
	if up, ok := tok.Claims["upgraded_from"].(map[string]any); ok {
		raw, _ := json.Marshal(up)
		item("provenance", "%s", raw)
	}
}

// call sends a resource request through the client and returns the TLS state.
func (r *runner) call(c xappclient.Client, url string) (int, string, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, string(body), resp.TLS, nil
}

// send crafts a request with explicit credentials, for the negative tests.
func (r *runner) send(url string, cert *tls.Certificate, headers map[string]string) (int, xappresource.RejectionBody, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.roots}
	if cert != nil {
		conf.Certificates = []tls.Certificate{*cert}
	}
	tr := netx.NewTransport(conf, r.overrides)
	tr.DisableKeepAlives = true
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, xappresource.RejectionBody{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var rb xappresource.RejectionBody
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(raw, &rb)
	}
	return resp.StatusCode, rb, nil
}

// methodSpecific shows what makes each method different.
func (r *runner) methodSpecific(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	switch m {
	case xappclient.MethodEphemeral:
		step("Key rotation (Method B)")
		before := client.Identity().Leaf().SerialNumber.Text(16)
		stats, err := client.Rotate(r.ctx)
		if err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		item("previous certificate", "serial %s", before)
		item("new certificate", "serial %s (%s, %d bytes)", stats.Serial, stats.KeyAlg, stats.CertBytes)
		item("rotation cost", "keygen %.2f ms, CA round trip %.2f ms", msOf(stats.KeyGen), msOf(stats.RoundTrip))
		// The token issued before rotation is bound to the retired certificate.
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), bearer(tok))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
			"token from before the rotation is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		if _, err := client.Token(r.ctx); err != nil {
			return fmt.Errorf("token after rotation: %w", err)
		}
		status, body, _, err := r.call(client, r.path(xappresource.ModeLocal))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "a token bound to the new certificate is accepted: HTTP %d %s", status, strings.TrimSpace(body))

	case xappclient.MethodDPoP:
		step("DPoP proof (Method C)")
		dp := client.(xappclient.DPoP)
		signer := dp.Signer()
		if tok.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), tok.Value, "", time.Now())
		if err != nil {
			return err
		}
		parsed, err := jose.ParseCompact(proof)
		if err != nil {
			return err
		}
		item("proof algorithm", "%s", parsed.Alg())
		item("proof size", "%d bytes", len(proof))
		item("proof key thumbprint", "%s", tok.Thumbprint)
		// First use is accepted, the replay of the same proof is not.
		status, _, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusOK, "first use of the proof is accepted (HTTP %d)", status)
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(client), dpopHeaders(tok, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPReplayed,
			"replaying the same proof is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
	}
	return nil
}

// negative is the core security claim for the method: the token alone is not enough.
func (r *runner) negative(m xappclient.Method, client xappclient.Client, tok *xappclient.Token) error {
	step("Negative test: the token alone must not be enough")
	other, err := r.newClient()
	if err != nil {
		return fmt.Errorf("second client: %w", err)
	}
	fresh, err := client.Token(r.ctx)
	if err != nil {
		return err
	}
	if m == xappclient.MethodDPoP {
		// Present the DPoP-bound token with a proof signed by another key.
		dp := other.(xappclient.DPoP)
		signer := dp.Signer()
		if fresh.PostQuantum {
			signer = dp.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, http.MethodGet, r.path(xappresource.ModeLocal), fresh.Value, "", time.Now())
		if err != nil {
			return err
		}
		status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), dpopHeaders(fresh, proof))
		if err != nil {
			return err
		}
		r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonDPoPJktMismatch,
			"stolen token with the attacker proof key is rejected: HTTP %d %s", status, rb.ReasonCode)
		item("reason", "%s", rb.Reason)
		return nil
	}
	// Methods A and B: present the token over another certificate, and with none.
	status, rb, err := r.send(r.path(xappresource.ModeLocal), r.activeCert(other), bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonX5tMismatch,
		"stolen token over another certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)

	status, rb, err = r.send(r.path(xappresource.ModeLocal), nil, bearer(fresh))
	if err != nil {
		return err
	}
	r.check(status == http.StatusUnauthorized && rb.ReasonCode == xappresource.ReasonClientCertMissing,
		"stolen token with no certificate is rejected: HTTP %d %s", status, rb.ReasonCode)
	item("reason", "%s", rb.Reason)
	return nil
}

// activeCert is the credential a resource server expects to see.
func (r *runner) activeCert(c xappclient.Client) *tls.Certificate {
	if r.pq && c.PQIdentity() != nil {
		return c.PQIdentity().Current()
	}
	return c.Identity().Current()
}

func bearer(tok *xappclient.Token) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok.Value}
}

func dpopHeaders(tok *xappclient.Token, proof string) map[string]string {
	return map[string]string{"Authorization": "DPoP " + tok.Value, "DPoP": proof}
}

func msOf(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
METHODRUN_MAIN_GO_EOF
```


## 8A.2 The run scripts

`_run-method.sh` is adapted from the reference project, which called
`make build` and `make host-env`. This build has no Makefile, so it builds directly
and calls `build/host-env.sh`.

```bash
cat > ~/pqc-xapp-auth/scripts/_run-method.sh <<'SCRIPTS_RUN_METHOD_SH_EOF'
#!/usr/bin/env bash
# Shared driver for scripts/run-method-{a,b,c}.sh.
#
#   _run-method.sh <A|B|C> [--pq|--classical]
#
# Runs one binding method end to end and prints, on the CLI:
#   - the configuration and algorithms in use,
#   - SMO onboarding and RIC CA enrollment (both credentials in post-quantum mode),
#   - the Keycloak token and, in post-quantum mode, its ML-DSA upgrade by the shim,
#   - the negotiated TLS key exchange group,
#   - resource calls under local validation and introspection,
#   - the method-specific behaviour (rotation for B, proof replay for C),
#   - the negative test that proves the token alone is not enough,
# followed by the matching decisions from the deployed components.
set -euo pipefail

METHOD=${1:?usage: _run-method.sh <A|B|C> [--pq]}
shift || true
MODE=classical
for arg in "$@"; do
  case "$arg" in
    --pq|-pq|pq) MODE=pq ;;
    --classical|-classical|classical) MODE=classical ;;
    *) echo "unknown option: $arg (use --pq or --classical)" >&2; exit 2 ;;
  esac
done

cd "$(dirname "$0")/.."
if [[ ! -x out/bin/methodrun ]]; then
  CGO_ENABLED=0 go build -p=2 -o out/bin/ ./cmd/methodrun
fi
if [[ ! -f out/host.env ]]; then
  set -a; source config/env.sh; set +a
  build/host-env.sh out/host.env
fi
set -a; source out/host.env; set +a

if [[ "$MODE" == pq && "${PQ_MODE:-false}" != true ]]; then
  echo "note: the deployed xApps are in classical mode, so the resource validator still" >&2
  echo "      trusts Keycloak. Redeploy with PQ_MODE=true (Chunk 8B) before using --pq." >&2
fi

FLAGS=(-method "$METHOD")
BANNER="classical (ECDSA P-256 signatures, X25519 key exchange)"
if [[ "$MODE" == pq ]]; then
  FLAGS+=(-pq)
  BANNER="post-quantum (${PQ_SIGNING_ALG:-ML-DSA-65} tokens, ${PQ_IDENTITY_KEY_ALG:-ML-DSA-65} certificates, X25519MLKEM768 key exchange)"
fi

echo "==============================================================================="
echo " Method $METHOD  --  $BANNER"
echo " resource xApp: ${RESOURCE_URL}"
echo "==============================================================================="

set +e
out/bin/methodrun "${FLAGS[@]}"
rc=$?
set -e

echo
echo "--- validator decisions recorded by the resource xApp -------------------------"
kubectl -n "${XAPP_NAMESPACE:-ricxapp}" logs "deploy/${XAPP_A_NAME:-xapp-a}" --since=3m 2>/dev/null \
  | grep -E 'authz_rejected|token_binding_missing' | tail -6 | cut -c1-320 || echo "(none)"

if [[ "$MODE" == pq ]]; then
  echo
  echo "--- token upgrades recorded by the pq-shim ------------------------------------"
  kubectl -n "${RICSEC_NAMESPACE:-ricsec}" logs "deploy/${PQ_SHIM_SERVICE:-pq-shim}" --since=3m 2>/dev/null \
    | grep -E 'token_upgraded|upgrade_rejected' | tail -4 | cut -c1-400 || echo "(none)"
fi

echo
echo "--- certificates issued by the RIC CA -----------------------------------------"
kubectl -n "${RICSEC_NAMESPACE:-ricsec}" logs "deploy/${RIC_CA_SERVICE:-ric-ca}" --since=3m 2>/dev/null \
  | grep certificate_issued | tail -4 | cut -c1-320 || echo "(none)"

exit $rc
SCRIPTS_RUN_METHOD_SH_EOF
```


```bash
cat > ~/pqc-xapp-auth/scripts/run-method-a.sh <<'SCRIPTS_RUN_METHOD_A_SH_EOF'
#!/usr/bin/env bash
# Method A end to end. Add --pq for the post-quantum plane.
exec "$(dirname "$0")/_run-method.sh" A "$@"
SCRIPTS_RUN_METHOD_A_SH_EOF
```


```bash
cat > ~/pqc-xapp-auth/scripts/run-method-b.sh <<'SCRIPTS_RUN_METHOD_B_SH_EOF'
#!/usr/bin/env bash
# Method B end to end. Add --pq for the post-quantum plane.
exec "$(dirname "$0")/_run-method.sh" B "$@"
SCRIPTS_RUN_METHOD_B_SH_EOF
```


```bash
cat > ~/pqc-xapp-auth/scripts/run-method-c.sh <<'SCRIPTS_RUN_METHOD_C_SH_EOF'
#!/usr/bin/env bash
# Method C end to end. Add --pq for the post-quantum plane.
exec "$(dirname "$0")/_run-method.sh" C "$@"
SCRIPTS_RUN_METHOD_C_SH_EOF
```


```bash
chmod +x ~/pqc-xapp-auth/scripts/*.sh
```

## 8A.3 Check, build, and prove it works *before* switching

```bash
cd ~/pqc-xapp-auth && for f in cmd/methodrun/main.go:505 scripts/_run-method.sh:77 scripts/run-method-a.sh:3 scripts/run-method-b.sh:3 scripts/run-method-c.sh:3; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `cmd/methodrun/main.go` | 505 |
| `scripts/_run-method.sh` | 77 |
| `scripts/run-method-a.sh` | 3 |
| `scripts/run-method-b.sh` | 3 |
| `scripts/run-method-c.sh` | 3 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && go vet ./cmd/methodrun/ && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./cmd/methodrun && ls -l out/bin/methodrun
```

The deployment is still classical. Run all three methods against it now - this is
ground the 46-case suite already covers, so a failure here is the CLI's fault, not the
post-quantum switch's:

```bash
cd ~/pqc-xapp-auth && ./scripts/run-method-a.sh && ./scripts/run-method-b.sh && ./scripts/run-method-c.sh
```

Each must end with **All checks passed.**, showing `alg=ES256`,
`binding=cnf.x5t#S256` (A and B) or `cnf.jkt` (C), and `TLS key exchange: X25519`.

---

# 8B - Switching the deployment

## 8B.1 Prerequisites from earlier chunks

Two edits belong in Chunk 3B's `ca/k8s/ric-ca.yaml` and must already be in place
before `PQ_MODE=true`. If you built from an earlier version of that chunk, apply them
now:

- **`strategy: {type: Recreate}`** - the one-time bootstrap ledger is local to the
  pod, so a RollingUpdate briefly runs two pods with two independent ledgers and a
  bootstrap credential could be spent twice. `replicas: 1` alone does not prevent it.
- **`tcpSocket: {port: https}`** readiness instead of `httpGet ... scheme: HTTPS` -
  the kubelet cannot complete a TLS handshake against an ML-DSA server certificate, so
  an HTTPS probe can never pass once the CA is post-quantum. The pod sits
  `0/1 Running` with zero restarts: the process is healthy, only the probe fails.

```bash
cd ~/pqc-xapp-auth && grep -n 'strategy:\|tcpSocket:\|httpGet:' ca/k8s/ric-ca.yaml
```

If `httpGet` is still there, or `strategy` is missing, fix `ca/k8s/ric-ca.yaml` and
recreate the Deployment. Changing an existing Deployment from RollingUpdate to
Recreate cannot be done with `apply` - the defaulted `rollingUpdate` field survives
the merge and the API rejects the combination - so delete and re-apply:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$RICSEC_NAMESPACE" delete deploy "$RIC_CA_SERVICE" --wait=true && build/render.sh ca/k8s/ric-ca.yaml | kubectl apply -f - && kubectl -n "$RICSEC_NAMESPACE" rollout status deploy/"$RIC_CA_SERVICE" --timeout=180s && kubectl -n "$RICSEC_NAMESPACE" get pods -l app=ric-ca
```

Exactly **one** pod, `1/1 Running`.

## 8B.2 Flip the flag

```bash
cd ~/pqc-xapp-auth && sed -i 's/^PQ_MODE=false$/PQ_MODE=true/' config/env.sh && grep -n '^PQ_MODE=' config/env.sh
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && printf '%s\n' "RESOURCE_TOKEN_ISSUER=$RESOURCE_TOKEN_ISSUER" "RESOURCE_JWKS_URL=$RESOURCE_JWKS_URL" "RESOURCE_INTROSPECTION_URL=$RESOURCE_INTROSPECTION_URL" "RIC_CA_SERVER_CERT=$RIC_CA_SERVER_CERT"
```

All four must have changed:

```
RESOURCE_TOKEN_ISSUER=https://pq-shim.ricsec.svc.cluster.local:8443
RESOURCE_JWKS_URL=https://pq-shim.ricsec.svc.cluster.local:8443/v1/jwks
RESOURCE_INTROSPECTION_URL=https://pq-shim.ricsec.svc.cluster.local:8443/v1/introspect
RIC_CA_SERVER_CERT=ric-ca-server-pq
```

> `config/env.sh` is edited in place across chunks, so its line count is not a useful
> check. These four derived values are.

## 8B.3 Give the RIC CA its ML-DSA server certificate

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && ls -l "out/pki/${RIC_CA_SERVER_CERT}-chain.crt" "out/pki/${RIC_CA_SERVER_CERT}.key"
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$RICSEC_NAMESPACE" create secret generic ric-ca-server-tls --from-file=tls.crt="out/pki/${RIC_CA_SERVER_CERT}-chain.crt" --from-file=tls.key="out/pki/${RIC_CA_SERVER_CERT}.key" --dry-run=client -o yaml | kubectl apply -f -
```

`kubectl` prints `Warning: tls: failed to parse private key`. That is kubectl's own
classical parser looking at an ML-DSA key; the Secret is created correctly and the Go
server reads it fine. Ignore it.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$RICSEC_NAMESPACE" rollout restart deploy/"$RIC_CA_SERVICE" && kubectl -n "$RICSEC_NAMESPACE" rollout status deploy/"$RIC_CA_SERVICE" --timeout=180s
```

OpenSSL cannot verify an ML-DSA signature, but it parses the ASN.1, so the issuer name
proves which branch the CA is serving:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$RICSEC_NAMESPACE" get secret ric-ca-server-tls -o 'jsonpath={.data.tls\.crt}' | base64 -d | openssl x509 -noout -subject -issuer
```

```
subject=O = O-RAN-RIC, OU = Near-RT RIC, CN = ric-ca.ricsec.svc.cluster.local
issuer=O = O-RAN-RIC, OU = Near-RT RIC, CN = RIC Intermediate CA PQ
```

> The CA's one-time ledger lives in an `emptyDir`, so this restart **cleared** it.
> Every bootstrap credential issued before now is spendable again - which is why the
> next step mints fresh ones rather than reusing anything.

## 8B.4 Re-mint the bootstrap credentials

Scale the xApps to zero first, so no pod can boot onto a half-written Secret:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" scale deploy "$XAPP_A_NAME" "$XAPP_B_NAME" --replicas=0 && kubectl -n "$XAPP_NAMESPACE" wait --for=delete pod -l part-of=pqc-xapp-auth --timeout=120s
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && export SMO_ONBOARDING_CERT="$PWD/out/pki/smo-onboarding-ca.crt" SMO_ONBOARDING_KEY="$PWD/out/pki/smo-onboarding-ca.key" && for pair in "$XAPP_A_NAME:$XAPP_A_CLIENT_ID" "$XAPP_B_NAME:$XAPP_B_CLIENT_ID"; do app=${pair%:*}; cid=${pair#*:}; dns="$app.$XAPP_NAMESPACE.svc.$CLUSTER_DOMAIN,$app.$XAPP_NAMESPACE.svc"; rm -rf "out/bootstrap/$app" "out/bootstrap/$app-pq"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$app" -validity "$BOOTSTRAP_CERT_VALIDITY"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$app-pq" -validity "$BOOTSTRAP_CERT_VALIDITY" -key-alg "$PQ_IDENTITY_KEY_ALG" -ca-cert "$PWD/out/pki/smo-onboarding-ca-pq.crt" -ca-key "$PWD/out/pki/smo-onboarding-ca-pq.key"; done
```

**Delete each Secret before recreating it.** A Secret's `type` is immutable, so if the
Secrets were ever created as `kubernetes.io/tls`, a `generic` update fails with
`type: Invalid value: "Opaque": field is immutable` - and the pods then restart onto
their already-spent credentials and crash-loop with
`403 {"error":"bootstrap_credential_reused"}`.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for app in "$XAPP_A_NAME" "$XAPP_B_NAME"; do for suffix in "" "-pq"; do kubectl -n "$XAPP_NAMESPACE" delete secret "${app}-bootstrap${suffix}" --ignore-not-found; kubectl -n "$XAPP_NAMESPACE" create secret generic "${app}-bootstrap${suffix}" --from-file=tls.crt="out/bootstrap/${app}${suffix}/tls.crt" --from-file=tls.key="out/bootstrap/${app}${suffix}/tls.key"; done; done
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" get secret -o custom-columns=NAME:.metadata.name,TYPE:.type | grep bootstrap
```

All four `Opaque`.

## 8B.5 Re-render, re-apply, restart

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh demo-xapp/k8s/xapps.yaml | grep -nE 'PQ_MODE|TOKEN_ISSUER|JWKS_URL|INTROSPECTION_URL|\${'
```

`PQ_MODE: "true"`, the three `RESOURCE_*` values on `pq-shim`, and **no line
containing `${`**. If any `${VAR}` survives, stop - that is the Chunk 6B failure.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh demo-xapp/k8s/xapps.yaml | kubectl apply -f - && kubectl -n "$XAPP_NAMESPACE" scale deploy "$XAPP_A_NAME" --replicas=1 && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_A_NAME" --timeout=180s && kubectl -n "$XAPP_NAMESPACE" scale deploy "$XAPP_B_NAME" --replicas=1 && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_B_NAME" --timeout=180s
```

## 8B.6 Regenerate the host environment

`out/host.env` carries `PQ_MODE`, `PQ_ISSUER` and the Service ClusterIPs, and
`_run-method.sh` only writes it when it is absent. Delete it:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && rm -f out/host.env && build/host-env.sh out/host.env && grep -E '^(PQ_MODE|PQ_ISSUER|PQ_SHIM_URL|DIAL_OVERRIDES)=' out/host.env
```

## 8B.7 Confirm the switch took

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" get cm pqc-xapp-auth -o 'jsonpath={.data.PQ_MODE}{"\n"}{.data.TOKEN_ISSUER}{"\n"}{.data.JWKS_URL}{"\n"}' && kubectl -n "$XAPP_NAMESPACE" logs "deploy/$XAPP_A_NAME" | grep -E 'identity_ready|pq_identity_ready|peer_call' | tail -6 | cut -c1-300
```

`pq_identity_ready` with `alg=ML-DSA-65`, and `peer_call` at `status=200`.

---

# 8C - All three methods, post-quantum

```bash
cd ~/pqc-xapp-auth && ./scripts/run-method-a.sh --pq
```

```bash
cd ~/pqc-xapp-auth && ./scripts/run-method-b.sh --pq
```

```bash
cd ~/pqc-xapp-auth && ./scripts/run-method-c.sh --pq
```

Each must end with **All checks passed.** and show, in order:

- `post-quantum certificate` with `identity certificate uses ML-DSA-65`
- `Keycloak token: alg=RS256` then `upgraded token: alg=ML-DSA-65`, with the size
  change - the number worth quoting
- `cnf value` - the ML-DSA certificate thumbprint for A/B, the `AKP` JWK thumbprint
  for C
- `provenance` - the `upgraded_from` claim naming the Keycloak token the shim consumed
- `TLS key exchange: X25519MLKEM768` and `key exchange is post-quantum`
- `server certificate: ML-DSA-65`
- for B, the rotation block and `token from before the rotation is rejected`
- for C, `proof algorithm: ML-DSA-44`, first use accepted, replay rejected
- the negative test rejecting a stolen token

Representative figures from a run on the lab VM:

| | Method A | Method B | Method C |
|---|---|---|---|
| Identity certificate | ML-DSA-65, 5660 B | 5662 B | 5652 B |
| Keycloak token | RS256, 1017 B | 1019 B | 997 B |
| Upgraded token | ML-DSA-65, 5352 B | 5355 B | 5328 B |
| Growth | **5.3x** (+4335 B) | 5.3x | 5.3x |
| DPoP proof | - | - | ML-DSA-44, **5920 B** |

The proof is larger than the token it accompanies. That is a real deployment
consideration for RMR-sized messages, and it is the kind of number this whole build
exists to produce.

## One expected refusal

The 46-case suite now **declines to run**, and that is correct - it drives the
classical path against a resource that no longer trusts Keycloak, so every case would
fail for the wrong reason:

```bash
cd ~/pqc-xapp-auth && set -a && source out/host.env && set +a && out/bin/sectest; echo "exit=$?"
```

Expected: `exit=2` and a message naming the shim.

## Going back

Nothing here is one-way: `sed -i 's/^PQ_MODE=true$/PQ_MODE=false/' config/env.sh`,
restore `ric-ca-server-tls` from `out/pki/ric-ca-server-chain.crt`, re-mint the
bootstrap credentials, re-render and restart. The 46 cases pass again. Chunk 11 needs
exactly this to produce the classical half of the comparison.

Next: `chunk-09-pq-tunnel.md`.
