# Chunk 6B - The demo xApps

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


**Goal:** two xApps in `ricxapp`, each holding a client and a validator, calling each
other's protected API. The first time anything is actually enforced.

**Needs the cluster?** Yes.

---

## What this demonstrates

`xapp-a` runs Method A and `xapp-b` runs Method B. Each is simultaneously an OAuth
client (it mints a bound token to call its peer) and a resource server (it validates
the token its peer presents). Both are the same binary; `XAPP_METHOD` decides which
client the library builds.

The manifest is worth reading for one reason: **the three `RESOURCE_*` values.** They
decide which issuer the validators trust - Keycloak now, the post-quantum shim from
Chunk 8 onwards - and they are computed in `config/env.sh`, not here.

> In the reference project those three values came from a Makefile conditional. This
> guide has no Makefile, so they are computed in `config/env.sh` instead, which is why
> that file is **sourced** rather than parsed. Getting this wrong is the single most
> expensive mistake available in this build: the ConfigMap ships the literal string
> `${RESOURCE_JWKS_URL}`, and every request is then refused with
> `token_key_unavailable: ... unsupported protocol scheme`. The check in 6B.5 exists
> specifically to catch it.

## 6B.1 The xApp

```bash
cat > ~/pqc-xapp-auth/demo-xapp/cmd/xapp/main.go <<'XAPP_MAIN_GO_EOF'
// Command xapp is a demo xApp that is both an OAuth client and a protected resource:
// it exposes an SDL-style API guarded by the xappresource validator and periodically
// calls its peer xApp with a sender-constrained token, so traffic flows both ways.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
	"github.com/oran-ricsec/pqc-xapp-auth/internal/logx"
	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

func main() {
	log := logx.New("xapp")
	e := &config.Env{}
	name := e.Req("XAPP_NAME")
	listen := e.Str("LISTEN_ADDR", ":8443")
	peerURL := e.Str("PEER_URL", "")
	peerInterval := e.Dur("PEER_INTERVAL", 30*time.Second)
	healthAddr := e.Str("HEALTH_ADDR", ":8081")
	if err := e.Err(); err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	ccfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	rcfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}
	log = log.With("xapp", name)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	client, err := xappclient.New(ccfg, log)
	if err != nil {
		log.Error("client", "error", err)
		os.Exit(1)
	}
	for attempt := 1; ; attempt++ {
		if err = client.Start(ctx); err == nil {
			break
		}
		log.Warn("enrollment_retry", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(time.Duration(attempt)*2*time.Second, 30*time.Second)):
		}
	}
	go client.Maintain(ctx)

	validator, err := xappresource.NewValidator(rcfg, client.HTTPClient(), log)
	if err != nil {
		log.Error("validator", "error", err)
		os.Exit(1)
	}

	sdl := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := xappresource.PrincipalFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"xapp":      name,
			"key":       strings.TrimPrefix(r.URL.Path[strings.LastIndex(r.URL.Path, "/"):], "/"),
			"value":     "demo-sdl-value",
			"caller":    p.ClientID,
			"binding":   p.Binding,
			"cnf":       p.Thumbprint,
			"validated": p.Mode,
		})
	})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("/api/v1/sdl/", validator.Middleware(xappresource.ModeLocal, sdl))
	mux.Handle("/api/v1/introspect/sdl/", validator.Middleware(xappresource.ModeIntrospection, sdl))

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		TLSConfig:         client.ServerTLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          nil,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	// Plain-HTTP health endpoint for Kubernetes probes: the kubelet cannot complete a
	// handshake on a TLS port pinned to the ML-KEM hybrid group.
	if healthAddr != "" {
		healthMux := http.NewServeMux()
		healthMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
		healthSrv := &http.Server{Addr: healthAddr, Handler: healthMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("health listener", "error", err)
			}
		}()
	}
	if peerURL != "" {
		go peerLoop(ctx, client, peerURL, peerInterval, log)
	}
	log.Info("listening", "addr", listen, "method", string(ccfg.Method), "client_id", ccfg.ClientID,
		"cert_lifetime", ccfg.CertLifetime.String(), "peer", peerURL)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
		os.Exit(1)
	}
}

// peerLoop calls the peer xApp's protected API with a sender-constrained token.
func peerLoop(ctx context.Context, c xappclient.Client, url string, every time.Duration, log interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Warn("peer_call_failed", "error", err)
			continue
		}
		start := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			log.Warn("peer_call_failed", "url", url, "error", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		leaf := c.Identity().Leaf()
		log.Info("peer_call", "url", url, "status", resp.StatusCode, "elapsed_ms", time.Since(start).Milliseconds(),
			"my_cert_serial", leaf.SerialNumber.Text(16), "my_cert_not_after", leaf.NotAfter.UTC().Format(time.RFC3339),
			"response", strings.TrimSpace(string(body)))
	}
}
XAPP_MAIN_GO_EOF
```


## 6B.2 The manifests

```bash
cat > ~/pqc-xapp-auth/demo-xapp/k8s/xapps.yaml <<'K8S_XAPPS_YAML_EOF'
# Two demo xApps in ricxapp, rendered from config/env.sh.
#   ${XAPP_A_NAME}: Method ${XAPP_A_METHOD} (client ${XAPP_A_CLIENT_ID}, certificate lifetime ${LONGTERM_CERT_LIFETIME})
#   ${XAPP_B_NAME}: Method ${XAPP_B_METHOD} (client ${XAPP_B_CLIENT_ID}, certificate lifetime ${EPHEMERAL_CERT_LIFETIME})
# Each calls the other's protected API every ${PEER_INTERVAL}.
apiVersion: v1
kind: ConfigMap
metadata:
  name: pqc-xapp-auth
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: pqc-xapp-auth}
data:
  KEYCLOAK_TOKEN_URL: "${TOKEN_ISSUER}/protocol/openid-connect/token"
  # The validator trusts whichever issuer is active for this deployment: Keycloak in
  # classical mode, the pq-shim in post-quantum mode (see RESOURCE_* in config/env.sh).
  INTROSPECTION_URL: "${RESOURCE_INTROSPECTION_URL}"
  JWKS_URL: "${RESOURCE_JWKS_URL}"
  TOKEN_ISSUER: "${RESOURCE_TOKEN_ISSUER}"
  TOKEN_AUDIENCE: "${TOKEN_AUDIENCE}"
  TOKEN_SCOPE: "${TOKEN_SCOPE}"
  REQUIRED_SCOPE: "${TOKEN_SCOPE}"
  REQUIRED_ROLE: "${REQUIRED_ROLE}"
  RIC_CA_URL: "${RIC_CA_URL}"
  RIC_TRUST_BUNDLE: "/etc/ric-trust/ric-intermediate-ca.crt,/etc/ric-trust/ric-intermediate-ca-pq.crt"
  BOOTSTRAP_CERT: /etc/xapp/bootstrap/tls.crt
  BOOTSTRAP_KEY: /etc/xapp/bootstrap/tls.key
  IDENTITY_DIR: /var/run/xapp/identity
  PQ_MODE: "${PQ_MODE}"
  PQ_ISSUER: "${PQ_ISSUER}"
  PQ_SHIM_URL: "${PQ_SHIM_URL}"
  PQ_IDENTITY_KEY_ALG: "${PQ_IDENTITY_KEY_ALG}"
  PQ_DPOP_ALG: "${PQ_DPOP_ALG}"
  PQ_KEX_ONLY: "${PQ_KEX_ONLY}"
  PQ_BOOTSTRAP_CERT: /etc/xapp/bootstrap-pq/tls.crt
  PQ_BOOTSTRAP_KEY: /etc/xapp/bootstrap-pq/tls.key
  PQ_IDENTITY_DIR: /var/run/xapp/identity-pq
  LISTEN_ADDR: ":${XAPP_PORT}"
  PEER_INTERVAL: "${PEER_INTERVAL}"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP_A_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_A_NAME}, part-of: pqc-xapp-auth}
spec:
  replicas: 1
  strategy: {type: Recreate}   # one-time bootstrap credential: old and new pods must never overlap
  selector:
    matchLabels: {app: ${XAPP_A_NAME}}
  template:
    metadata:
      labels: {app: ${XAPP_A_NAME}, part-of: pqc-xapp-auth}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: xapp
          image: ricsec/xapp:${IMAGE_TAG}
          imagePullPolicy: Never
          envFrom: [{configMapRef: {name: pqc-xapp-auth}}]
          env:
            - {name: XAPP_NAME, value: "${XAPP_A_NAME}"}
            - {name: XAPP_METHOD, value: "${XAPP_A_METHOD}"}
            - {name: XAPP_CLIENT_ID, value: "${XAPP_A_CLIENT_ID}"}
            - {name: CERT_LIFETIME, value: "${LONGTERM_CERT_LIFETIME}"}
            - {name: SERVER_DNS_NAMES, value: "${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc"}
            - {name: PEER_URL, value: "https://${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${XAPP_PORT}/api/v1/sdl/demo-key"}
          ports:
            - {name: https, containerPort: ${XAPP_PORT}}
            - {name: health, containerPort: 8081}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          volumeMounts:
            - {name: bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
            - {name: bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: identity, mountPath: /var/run/xapp/identity}
            - {name: identity-pq, mountPath: /var/run/xapp/identity-pq}
          resources:
            requests: {cpu: 20m, memory: 24Mi}
            limits: {memory: 96Mi}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes:
        - {name: bootstrap, secret: {secretName: "${XAPP_A_NAME}-bootstrap", defaultMode: 0440}}
        - {name: bootstrap-pq, secret: {secretName: "${XAPP_A_NAME}-bootstrap-pq", defaultMode: 0440}}
        - {name: trust, configMap: {name: ric-trust}}
        - {name: identity, emptyDir: {medium: Memory}}
        - {name: identity-pq, emptyDir: {medium: Memory}}
---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP_A_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_A_NAME}, part-of: pqc-xapp-auth}
spec:
  selector: {app: ${XAPP_A_NAME}}
  ports: [{name: https, port: ${XAPP_PORT}, targetPort: https}]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${XAPP_B_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_B_NAME}, part-of: pqc-xapp-auth}
spec:
  replicas: 1
  strategy: {type: Recreate}   # one-time bootstrap credential: old and new pods must never overlap
  selector:
    matchLabels: {app: ${XAPP_B_NAME}}
  template:
    metadata:
      labels: {app: ${XAPP_B_NAME}, part-of: pqc-xapp-auth}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: xapp
          image: ricsec/xapp:${IMAGE_TAG}
          imagePullPolicy: Never
          envFrom: [{configMapRef: {name: pqc-xapp-auth}}]
          env:
            - {name: XAPP_NAME, value: "${XAPP_B_NAME}"}
            - {name: XAPP_METHOD, value: "${XAPP_B_METHOD}"}
            - {name: XAPP_CLIENT_ID, value: "${XAPP_B_CLIENT_ID}"}
            - {name: CERT_LIFETIME, value: "${EPHEMERAL_CERT_LIFETIME}"}
            - {name: SERVER_DNS_NAMES, value: "${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},${XAPP_B_NAME}.${XAPP_NAMESPACE}.svc"}
            - {name: PEER_URL, value: "https://${XAPP_A_NAME}.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${XAPP_PORT}/api/v1/sdl/demo-key"}
          ports:
            - {name: https, containerPort: ${XAPP_PORT}}
            - {name: health, containerPort: 8081}
          readinessProbe:
            httpGet: {path: /healthz, port: health, scheme: HTTP}
            periodSeconds: 10
            timeoutSeconds: 5
          volumeMounts:
            - {name: bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
            - {name: bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: identity, mountPath: /var/run/xapp/identity}
            - {name: identity-pq, mountPath: /var/run/xapp/identity-pq}
          resources:
            requests: {cpu: 20m, memory: 24Mi}
            limits: {memory: 96Mi}
          securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      volumes:
        - {name: bootstrap, secret: {secretName: "${XAPP_B_NAME}-bootstrap", defaultMode: 0440}}
        - {name: bootstrap-pq, secret: {secretName: "${XAPP_B_NAME}-bootstrap-pq", defaultMode: 0440}}
        - {name: trust, configMap: {name: ric-trust}}
        - {name: identity, emptyDir: {medium: Memory}}
        - {name: identity-pq, emptyDir: {medium: Memory}}
---
apiVersion: v1
kind: Service
metadata:
  name: ${XAPP_B_NAME}
  namespace: ${XAPP_NAMESPACE}
  labels: {app: ${XAPP_B_NAME}, part-of: pqc-xapp-auth}
spec:
  selector: {app: ${XAPP_B_NAME}}
  ports: [{name: https, port: ${XAPP_PORT}, targetPort: https}]
K8S_XAPPS_YAML_EOF
```


## 6B.3 Check and build

```bash
cd ~/pqc-xapp-auth && for f in demo-xapp/cmd/xapp/main.go:160 demo-xapp/k8s/xapps.yaml:161; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `demo-xapp/cmd/xapp/main.go` | 160 |
| `demo-xapp/k8s/xapps.yaml` | 161 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./demo-xapp/cmd/xapp && ls -l out/bin/xapp
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && sudo docker build -q --build-arg BIN=xapp -t "ricsec/xapp:${IMAGE_TAG}" -f build/Dockerfile out/bin && sudo docker save "ricsec/xapp:${IMAGE_TAG}" | sudo ctr -n k8s.io images import - && sudo ctr -n k8s.io images ls -q | grep 'ricsec/xapp:'
```

## 6B.4 Trust anchors in the xApp namespace

Public certificates only - no private keys leave `out/pki`.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" create configmap ric-trust --from-file=out/pki/ric-intermediate-ca.crt --from-file=out/pki/ric-intermediate-ca-pq.crt --from-file=out/pki/smo-onboarding-ca.crt --from-file=out/pki/smo-onboarding-ca-pq.crt --from-file=out/pki/smo-root-ca.crt --dry-run=client -o yaml | kubectl apply -f - && kubectl -n "$XAPP_NAMESPACE" get configmap ric-trust -o jsonpath='{range $k,$v := .data}{$k}{"\n"}{end}'
```

Five entries. The `-pq` ones matter from Chunk 8 onwards; publish them now so no step
later has to touch this ConfigMap.

## 6B.5 Render the manifest - and check it

**Run this before applying anything.** A surviving `${...}` means `config/env.sh` is
missing a variable, and the only symptom later is a refused request.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh demo-xapp/k8s/xapps.yaml | grep -n '\${' && echo "UNSUBSTITUTED - fix config/env.sh before applying" || echo "clean: every variable resolved"
```

A broader version of the same check, across every manifest in the project:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for f in $(find . -name '*.yaml' -path '*/k8s/*' -o -path './deploy/*' -name '*.yaml' | sort -u); do miss=$(build/render.sh "$f" 2>/dev/null | grep -o '\${[A-Z_][A-Z0-9_]*}' | sort -u); [ -n "$miss" ] && printf '%-40s %s\n' "$f" "$miss"; done; echo "(no rows above = every manifest fully resolved)"
```

## 6B.6 Bootstrap credentials

One-time, and both planes - the post-quantum credential is minted now even though
`PQ_MODE` is still `false`, so Chunk 8 does not have to revisit this step.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && export SMO_ONBOARDING_CERT="$PWD/out/pki/smo-onboarding-ca.crt" SMO_ONBOARDING_KEY="$PWD/out/pki/smo-onboarding-ca.key" && for pair in "$XAPP_A_NAME:$XAPP_A_CLIENT_ID" "$XAPP_B_NAME:$XAPP_B_CLIENT_ID"; do app=${pair%:*}; cid=${pair#*:}; dns="$app.$XAPP_NAMESPACE.svc.$CLUSTER_DOMAIN,$app.$XAPP_NAMESPACE.svc"; rm -rf "out/bootstrap/$app" "out/bootstrap/$app-pq"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$app" -validity "$BOOTSTRAP_CERT_VALIDITY"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$app-pq" -validity "$BOOTSTRAP_CERT_VALIDITY" -key-alg "$PQ_IDENTITY_KEY_ALG" -ca-cert "$PWD/out/pki/smo-onboarding-ca-pq.crt" -ca-key "$PWD/out/pki/smo-onboarding-ca-pq.key"; done
```

Four credentials: two `EC-P-256`, two `ML-DSA-65`, each with its own serial.

Into Secrets. **Use `generic`, consistently** - the manifest mounts `tls.crt` and
`tls.key` by name and never looks at the Secret type, and a Secret's `type` field is
immutable once set, so mixing `create secret tls` here makes every later update fail
with `type: Invalid value: "Opaque": field is immutable`.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for app in "$XAPP_A_NAME" "$XAPP_B_NAME"; do for suffix in "" "-pq"; do kubectl -n "$XAPP_NAMESPACE" delete secret "${app}-bootstrap${suffix}" --ignore-not-found; kubectl -n "$XAPP_NAMESPACE" create secret generic "${app}-bootstrap${suffix}" --from-file=tls.crt="out/bootstrap/${app}${suffix}/tls.crt" --from-file=tls.key="out/bootstrap/${app}${suffix}/tls.key"; done; done
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" get secret -o custom-columns=NAME:.metadata.name,TYPE:.type | grep bootstrap
```

All four must say `Opaque`.

## 6B.7 Deploy

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh demo-xapp/k8s/xapps.yaml | kubectl apply -f - && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_A_NAME" --timeout=300s && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_B_NAME" --timeout=300s
```

## 6B.8 Verify

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs "deploy/$XAPP_A_NAME" | grep -E 'identity_ready|listening|peer_call' | tail -6 | cut -c1-300
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs "deploy/$XAPP_B_NAME" | grep peer_call | tail -3 | cut -c1-300
```

Both directions must show `"status":200`. A `401` with a `reason_code` means the
binding is being enforced but something is misconfigured; read the code.

Next: `chunk-06c-security-suite.md`.
