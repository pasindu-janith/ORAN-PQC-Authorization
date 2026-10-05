# Chunk 7B - Deploying the shim

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


**Goal:** `pq-shim` running in `ricsec`, presenting an ML-DSA server certificate over
an ML-KEM-only key exchange, and proven to be doing so.

**Needs the cluster?** Yes.

---

## 7B.1 The manifest

Two things to notice. The server certificate is the **ML-DSA** one from Chunk 1
(`pq-shim-server-pq`), and `PQ_KEX_ONLY` makes the shim require `X25519MLKEM768`. And
the health port is **plain HTTP on 8081** - the kubelet is a classical TLS client and
cannot complete a handshake against an ML-DSA certificate, so an HTTPS readiness probe
on the tunnel port could never pass.

```bash
cat > ~/pqc-xapp-auth/pqshim/k8s/pq-shim.yaml <<'K8S_PQ_SHIM_YAML_EOF'
# Post-quantum token shim: upgrades a classical Keycloak token into an ML-DSA-signed
# token bound to the caller post-quantum credential. Rendered from config/testbed.env.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${PQ_SHIM_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${PQ_SHIM_SERVICE}, part-of: pqc-xapp-auth}
spec:
  replicas: 1
  strategy: {type: Recreate}   # the signing key is generated per pod
  selector:
    matchLabels: {app: ${PQ_SHIM_SERVICE}}
  template:
    metadata:
      labels: {app: ${PQ_SHIM_SERVICE}, part-of: pqc-xapp-auth}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: pq-shim
          image: ricsec/pq-shim:${IMAGE_TAG}
          imagePullPolicy: Never
          ports:
            - {name: https, containerPort: ${PQ_SHIM_PORT}}
            - {name: health, containerPort: 8081}
          env:
            - {name: LISTEN_ADDR, value: ":${PQ_SHIM_PORT}"}
            # Post-quantum server certificate (ML-DSA) and the ML-KEM hybrid group.
            - {name: SERVER_CERT, value: /etc/pq-shim/server/tls.crt}
            - {name: SERVER_KEY, value: /etc/pq-shim/server/tls.key}
            - {name: PQ_KEX_ONLY, value: "${PQ_KEX_ONLY}"}
            # Identity of the tokens this shim issues. Deliberately NOT called
            # PQ_ISSUER: that name is the client-side shim|keycloak selector.
            - {name: PQ_TOKEN_ISSUER, value: "${PQ_SHIM_URL}"}
            - {name: PQ_SIGNING_ALG, value: "${PQ_SIGNING_ALG}"}
            - {name: PQ_TOKEN_LIFETIME, value: "${PQ_TOKEN_LIFETIME}"}
            # Trust anchor for the post-quantum certificate chains presented in x5c.
            - {name: PQ_TRUST_BUNDLE, value: /etc/ric-trust/ric-intermediate-ca-pq.crt}
            # Embedded validator: checks the incoming classical Keycloak token.
            - {name: TOKEN_ISSUER, value: "${TOKEN_ISSUER}"}
            - {name: JWKS_URL, value: "${TOKEN_ISSUER}/protocol/openid-connect/certs"}
            - {name: TOKEN_AUDIENCE, value: "${TOKEN_AUDIENCE}"}
            - {name: REQUIRED_SCOPE, value: "${TOKEN_SCOPE}"}
            - {name: REQUIRED_ROLE, value: "${REQUIRED_ROLE}"}
            - {name: RIC_TRUST_BUNDLE, value: /etc/ric-trust/ric-intermediate-ca.crt}
          volumeMounts:
            - {name: server-tls, mountPath: /etc/pq-shim/server, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          resources:
            requests: {cpu: 50m, memory: 32Mi}
            limits: {memory: 192Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
      volumes:
        - name: server-tls
          secret: {secretName: pq-shim-server-tls, defaultMode: 0440}
        - name: trust
          configMap: {name: ric-trust}
---
apiVersion: v1
kind: Service
metadata:
  name: ${PQ_SHIM_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${PQ_SHIM_SERVICE}, part-of: pqc-xapp-auth}
spec:
  selector: {app: ${PQ_SHIM_SERVICE}}
  ports:
    - {name: https, port: ${PQ_SHIM_PORT}, targetPort: https}
K8S_PQ_SHIM_YAML_EOF
```


## 7B.2 The server certificate

`kubectl create secret tls` runs the key pair through Go's classical
`tls.X509KeyPair`, which cannot parse an ML-DSA key. Use `generic` with the same two
keys - that is all the manifest mounts.

```bash
cd ~/pqc-xapp-auth && ls -l out/pki/pq-shim-server-pq-chain.crt out/pki/pq-shim-server-pq.key
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$RICSEC_NAMESPACE" delete secret pq-shim-server-tls --ignore-not-found && kubectl -n "$RICSEC_NAMESPACE" create secret generic pq-shim-server-tls --from-file=tls.crt=out/pki/pq-shim-server-pq-chain.crt --from-file=tls.key=out/pki/pq-shim-server-pq.key
```

## 7B.3 Build the image and deploy

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && sudo docker build -q --build-arg BIN=pq-shim -t "ricsec/pq-shim:${IMAGE_TAG}" -f build/Dockerfile out/bin && sudo docker save "ricsec/pq-shim:${IMAGE_TAG}" | sudo ctr -n k8s.io images import - && sudo ctr -n k8s.io images ls -q | grep pq-shim
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh pqshim/k8s/pq-shim.yaml | grep -n '\${' && echo "UNSUBSTITUTED - stop" || echo "clean"
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh pqshim/k8s/pq-shim.yaml | kubectl apply -f - && kubectl -n "$RICSEC_NAMESPACE" rollout status deploy/"$PQ_SHIM_SERVICE" --timeout=180s
```

## 7B.4 Verifying a post-quantum endpoint - why `curl` cannot

The obvious check is `curl https://pq-shim.../healthz`. It will not work, and the
reason is worth understanding rather than working around:

```
curl: (35) error:1408F10B:SSL routines:ssl3_get_record:wrong version number
       ... or: sslv3 alert handshake failure
```

`curl` on Ubuntu 20.04 links against OpenSSL 1.1.1, which predates both
`X25519MLKEM768` and ML-DSA. With `PQ_KEX_ONLY=true` and an ML-DSA server
certificate, there is no overlap: the handshake cannot complete. **This is the
expected result, not a misconfiguration** - and a check that can never pass is worse
than no check.

Go 1.27 supports both, so a small probe does the job properly.

```bash
cat > ~/pqc-xapp-auth/cmd/pqprobe/main.go <<'PQPROBE_MAIN_GO_EOF'
// Command pqprobe opens one TLS connection and reports what was actually negotiated.
//
// It exists because curl cannot do this job: the lab node links against OpenSSL
// 1.1.1, which predates both X25519MLKEM768 and ML-DSA, so a post-quantum endpoint
// refuses its handshake outright. Go's standard library supports both, so a six-line
// dial tells us what the server really offers.
//
//	pqprobe -url https://pq-shim.ricsec.svc.cluster.local:8443/healthz
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/netx"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

func main() {
	raw := flag.String("url", "", "https URL to probe (required)")
	timeout := flag.Duration("timeout", 15*time.Second, "overall timeout")
	flag.Parse()
	if *raw == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := probe(*raw, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "pqprobe:", err)
		os.Exit(1)
	}
}

func probe(raw string, timeout time.Duration) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	e := &config.Env{}
	bundle := e.List("RIC_TRUST_BUNDLE", nil)
	overrides, err := netx.ParseDialOverrides(e.Str("DIAL_OVERRIDES", ""))
	if err != nil {
		e.Fail("DIAL_OVERRIDES: %v", err)
	}
	if err := e.Err(); err != nil {
		return err
	}
	roots, err := pki.LoadCertPool(bundle...)
	if err != nil {
		return err
	}

	tr := netx.NewTransport(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, overrides)
	defer tr.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	cs := resp.TLS
	if cs == nil {
		return fmt.Errorf("%s is not TLS", u.Host)
	}
	fmt.Printf("host              %s\n", u.Host)
	fmt.Printf("status            HTTP %d %s\n", resp.StatusCode, trim(string(body)))
	fmt.Printf("tls version       0x%x\n", cs.Version)
	fmt.Printf("key exchange      %s\n", cs.CurveID)
	fmt.Printf("post-quantum kex  %v\n", netx.IsPQKex(cs.CurveID))
	fmt.Printf("cipher suite      %s\n", tls.CipherSuiteName(cs.CipherSuite))
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		fmt.Printf("server cert       %s\n", pki.DescribeCert(leaf))
		fmt.Printf("server key alg    %s\n", pki.KeyAlgName(leaf.PublicKey))
		fmt.Printf("post-quantum cert %v\n", pki.IsPostQuantum(leaf.PublicKey))
	}
	return nil
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
PQPROBE_MAIN_GO_EOF
```


## 7B.5 Check, build, probe

```bash
cd ~/pqc-xapp-auth && for f in pqshim/k8s/pq-shim.yaml:80 cmd/pqprobe/main.go:98; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `pqshim/k8s/pq-shim.yaml` | 80 |
| `cmd/pqprobe/main.go` | 98 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./cmd/pqprobe && ls -l out/bin/pqprobe
```

`out/host.env` predates the `pq-shim` Service, so its `DIAL_OVERRIDES` does not
contain the shim yet. Regenerate it, or the probe fails with a DNS lookup error that
looks like a networking problem and is not:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && rm -f out/host.env && build/host-env.sh out/host.env && grep '^DIAL_OVERRIDES=' out/host.env | tr ',' '\n'
```

Five entries, including `pq-shim.ricsec.svc.cluster.local:8443`.

```bash
cd ~/pqc-xapp-auth && set -a && source out/host.env && set +a && out/bin/pqprobe -url "$PQ_SHIM_URL/healthz"
```

Expected:

```
host              pq-shim.ricsec.svc.cluster.local:8443
status            HTTP 200 ok
tls version       0x304
key exchange      X25519MLKEM768
post-quantum kex  true
server cert       CN=pq-shim.ricsec.svc.cluster.local key=ML-DSA-65 sig=ML-DSA-65 ...
server key alg    ML-DSA-65
post-quantum cert true
```

And the JWKS it will sign with - `kty: "AKP"` is the RFC 9964 key type for ML-DSA:

```bash
cd ~/pqc-xapp-auth && set -a && source out/host.env && set +a && out/bin/pqprobe -url "$PQ_SHIM_URL/v1/jwks" 2>&1 | grep -E 'status|key exchange|server key alg'
```

The body line should contain `"kty":"AKP"` and `"alg":"ML-DSA-65"`.

---

**State after Chunk 7:** the shim is deployed and verified, but **nothing uses it**.
`PQ_MODE` is still `false`, the xApps still trust Keycloak directly, and the 46 cases
still pass. Chunk 8 switches the client plane over.

Next: `chunk-08-pq-client-plane.md`.
