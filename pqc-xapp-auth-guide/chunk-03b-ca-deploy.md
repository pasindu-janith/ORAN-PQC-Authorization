# Chunk 3B - Deploy the CA and prove one-time onboarding

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** the first component of the framework running in your RIC, with Milestone 1
passing.

**Needs the cluster?** Yes.

---

## 3B.1 The container image definition

One statically linked binary in an empty image. No base OS, no shell, no package
manager - which is why these images are about 10 MB with no CVE surface.

```bash
cat > ~/pqc-xapp-auth/build/Dockerfile <<'EOF'
# Minimal image for one statically linked binary from out/bin (the build context).
FROM scratch
ARG BIN
COPY ${BIN} /app
USER 65532:65532
ENTRYPOINT ["/app"]
EOF
```


## 3B.2 The manifest renderer

Manifests carry `${VAR}` placeholders filled from `config/env.sh`.

```bash
which envsubst || sudo apt-get install -y gettext-base
```

```bash
cat > ~/pqc-xapp-auth/build/render.sh <<'EOF'
#!/usr/bin/env bash
# render.sh <template>
# Substitutes only the variables defined in config/env.sh (including those assigned
# inside an if block), leaving every other '$' in the template untouched.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
vars=$(sed -n 's/^[[:space:]]*\([A-Z_][A-Z0-9_]*\)=.*/${\1}/p' "$ROOT/config/env.sh" | tr '\n' ' ')
envsubst "$vars" < "$1"
EOF
```


```bash
chmod +x ~/pqc-xapp-auth/build/render.sh
```

## 3B.3 The Deployment and Service

`replicas: 1` is deliberate and worth being able to explain: the one-time ledger is a
file local to the pod, so two replicas would each accept the same bootstrap credential
once. Making that ledger distributed is a stated limitation, not something solved here.

```bash
cat > ~/pqc-xapp-auth/ca/k8s/ric-ca.yaml <<'EOF'
# RIC intermediate CA enrollment service (rendered with envsubst from config/env.sh).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${RIC_CA_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${RIC_CA_SERVICE}, part-of: pqc-xapp-auth}
spec:
  replicas: 1   # the one-time bootstrap ledger is local to the pod
  selector:
    matchLabels: {app: ${RIC_CA_SERVICE}}
  template:
    metadata:
      labels: {app: ${RIC_CA_SERVICE}, part-of: pqc-xapp-auth}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: ric-ca
          image: ricsec/ric-ca:${IMAGE_TAG}
          imagePullPolicy: Never
          ports:
            - {name: https, containerPort: ${RIC_CA_PORT}}
          env:
            - {name: LISTEN_ADDR, value: ":${RIC_CA_PORT}"}
            - {name: SERVER_CERT, value: /etc/ric-ca/server/tls.crt}
            - {name: SERVER_KEY, value: /etc/ric-ca/server/tls.key}
            - {name: ISSUER_CERT, value: /etc/ric-ca/issuer/tls.crt}
            - {name: ISSUER_KEY, value: /etc/ric-ca/issuer/tls.key}
            # Post-quantum issuing branch: an ML-DSA CSR is signed by this CA.
            - {name: ISSUER_CERT_PQ, value: /etc/ric-ca/issuer-pq/tls.crt}
            - {name: ISSUER_KEY_PQ, value: /etc/ric-ca/issuer-pq/tls.key}
            - {name: BOOTSTRAP_TRUST_BUNDLE, value: "/etc/ric-trust/smo-onboarding-ca.crt,/etc/ric-trust/smo-onboarding-ca-pq.crt"}
            - {name: OPERATIONAL_TRUST_BUNDLE, value: "/etc/ric-trust/ric-intermediate-ca.crt,/etc/ric-trust/ric-intermediate-ca-pq.crt"}
            - {name: PQ_KEX_ONLY, value: "false"}
            - {name: STATE_DIR, value: /var/lib/ric-ca}
            - {name: ORG, value: "${ORG}"}
            - {name: XAPP_OU, value: "${XAPP_OU}"}
            - {name: CA_DEFAULT_LEAF_LIFETIME, value: "${CA_DEFAULT_LEAF_LIFETIME}"}
            - {name: CA_MIN_LEAF_LIFETIME, value: "${CA_MIN_LEAF_LIFETIME}"}
            - {name: CA_MAX_LEAF_LIFETIME, value: "${CA_MAX_LEAF_LIFETIME}"}
            - {name: ALLOWED_DNS_SUFFIXES, value: ".${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN},.${XAPP_NAMESPACE}.svc"}
          volumeMounts:
            - {name: server-tls, mountPath: /etc/ric-ca/server, readOnly: true}
            - {name: issuer, mountPath: /etc/ric-ca/issuer, readOnly: true}
            - {name: issuer-pq, mountPath: /etc/ric-ca/issuer-pq, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: state, mountPath: /var/lib/ric-ca}
          readinessProbe:
            httpGet: {path: /healthz, port: https, scheme: HTTPS}
            periodSeconds: 5
          resources:
            requests: {cpu: 20m, memory: 16Mi}
            limits: {memory: 64Mi}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
      volumes:
        - name: server-tls
          secret: {secretName: ric-ca-server-tls, defaultMode: 0440}
        - name: issuer
          secret: {secretName: ric-ca-issuer, defaultMode: 0440}
        - name: issuer-pq
          secret: {secretName: ric-ca-issuer-pq, defaultMode: 0440}
        - name: trust
          configMap: {name: ric-trust}
        - name: state
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${RIC_CA_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${RIC_CA_SERVICE}, part-of: pqc-xapp-auth}
spec:
  selector: {app: ${RIC_CA_SERVICE}}
  ports:
    - {name: https, port: ${RIC_CA_PORT}, targetPort: https}
EOF
```


## 3B.4 Build the image and load it into containerd

```bash
cd ~/pqc-xapp-auth && sudo docker build --build-arg BIN=ric-ca -t ricsec/ric-ca:0.1.0 -f build/Dockerfile out/bin
```

```bash
sudo docker save ricsec/ric-ca:0.1.0 | sudo ctr -n k8s.io images import -
```

The `k8s.io` containerd namespace is what the kubelet reads - that is what makes
`imagePullPolicy: Never` work without a registry.

## 3B.5 Namespace, secrets, trust bundle

```bash
kubectl create namespace ricsec
```

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create secret generic ric-ca-server-tls --type=kubernetes.io/tls --from-file=tls.crt=out/pki/ric-ca-server-chain.crt --from-file=tls.key=out/pki/ric-ca-server.key
```

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create secret tls ric-ca-issuer --cert=out/pki/ric-intermediate-ca.crt --key=out/pki/ric-intermediate-ca.key
```

The ML-DSA issuer **must** use `create secret generic --type=kubernetes.io/tls`, not
`create secret tls`: `kubectl` 1.28 parses the key client-side to validate the pair and
cannot parse an ML-DSA key.

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create secret generic ric-ca-issuer-pq --type=kubernetes.io/tls --from-file=tls.crt=out/pki/ric-intermediate-ca-pq.crt --from-file=tls.key=out/pki/ric-intermediate-ca-pq.key
```

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create configmap ric-trust --from-file=out/pki/ric-intermediate-ca.crt --from-file=out/pki/ric-intermediate-ca-pq.crt --from-file=out/pki/smo-onboarding-ca.crt --from-file=out/pki/smo-onboarding-ca-pq.crt --from-file=out/pki/smo-root-ca.crt
```

## 3B.6 Deploy

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; build/render.sh ca/k8s/ric-ca.yaml | kubectl apply -f -
```

```bash
kubectl -n ricsec rollout status deploy/ric-ca --timeout=120s && kubectl -n ricsec get pods,svc
```

Not Ready? `kubectl -n ricsec logs deploy/ric-ca` - the config loader reports *every*
missing variable at once.

## 3B.7 Milestone 1

```bash
cat > ~/pqc-xapp-auth/build/verify-ca.sh <<'EOF'
#!/usr/bin/env bash
# Milestone 1: the RIC CA issues a leaf on demand, the chain verifies with openssl,
# lifetime is a request parameter, and a bootstrap credential works exactly once.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${ORG:?source config/env.sh first}"

PKI=out/pki
HOST="${RIC_CA_SERVICE}.${RICSEC_NAMESPACE}.svc.${CLUSTER_DOMAIN}"
IP=$(kubectl -n "$RICSEC_NAMESPACE" get svc "$RIC_CA_SERVICE" -o jsonpath='{.spec.clusterIP}')
[[ -n "$IP" ]] || { echo "no ClusterIP for $RIC_CA_SERVICE"; exit 1; }
URL="https://${HOST}:${RIC_CA_PORT}"
RESOLVE="${HOST}:${RIC_CA_PORT}:${IP}"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

enroll() { # enroll <cred-dir> <lifetime> <out-file> <endpoint>
  curl -sS --tlsv1.3 --resolve "$RESOLVE" --cacert "$PKI/ric-intermediate-ca.crt" \
    --cert "$1/tls.crt" --key "$1/tls.key" \
    -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/req.csr" \
    -o "$3" -w '%{http_code}' "$URL/v1/$4?lifetime=$2"
}

echo "==> SMO onboarding: a one-time bootstrap credential for 'ca-smoke-test'"
out/bin/smo-sim -cn ca-smoke-test -validity 10m -out "$WORK/boot" -org "$ORG" \
  -ca-cert "$PKI/smo-onboarding-ca.crt" -ca-key "$PKI/smo-onboarding-ca.key"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/leaf.key" 2>/dev/null
openssl req -new -key "$WORK/leaf.key" -subj "/CN=ignored-by-ca" -out "$WORK/req.csr"

echo "==> Enroll with the bootstrap credential (lifetime=$EPHEMERAL_CERT_LIFETIME)"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/leaf.pem" enroll)
[[ "$code" == 200 ]] || { echo "FAIL: enroll returned $code: $(cat "$WORK/leaf.pem")"; exit 1; }
openssl x509 -in "$WORK/leaf.pem" -noout -subject -issuer -serial -startdate -enddate

echo "==> Note the subject: the CA overrode the CSR's /CN=ignored-by-ca"

echo "==> openssl verify (anchor: SMO root, untrusted intermediate: RIC CA)"
openssl verify -CAfile "$PKI/smo-root-ca.crt" -untrusted "$PKI/ric-intermediate-ca.crt" -purpose sslclient "$WORK/leaf.pem"

echo "==> Reusing the SAME bootstrap credential must be refused"
code=$(enroll "$WORK/boot" "$EPHEMERAL_CERT_LIFETIME" "$WORK/reuse.json" enroll)
echo "HTTP $code $(cat "$WORK/reuse.json")"
[[ "$code" == 403 ]] || { echo "FAIL: bootstrap reuse was not rejected"; exit 1; }

echo "==> Renew with the new operational certificate, long lifetime, same code path"
mkdir -p "$WORK/op" && cp "$WORK/leaf.pem" "$WORK/op/tls.crt" && cp "$WORK/leaf.key" "$WORK/op/tls.key"
code=$(enroll "$WORK/op" "$LONGTERM_CERT_LIFETIME" "$WORK/long.pem" renew)
[[ "$code" == 200 ]] || { echo "FAIL: renew returned $code: $(cat "$WORK/long.pem")"; exit 1; }
openssl x509 -in "$WORK/long.pem" -noout -subject -startdate -enddate
openssl verify -CAfile "$PKI/smo-root-ca.crt" -untrusted "$PKI/ric-intermediate-ca.crt" "$WORK/long.pem"

echo
echo "MILESTONE 1 PASSED"
EOF
```


```bash
chmod +x ~/pqc-xapp-auth/build/verify-ca.sh
```

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; build/verify-ca.sh
```

| Step | Proves |
|---|---|
| Enroll returns 200 with `CN=ca-smoke-test` | the CA authenticated the bootstrap credential and **set the subject itself** - the CSR said `/CN=ignored-by-ca` |
| `openssl verify` succeeds | the chain is real and anchors to the SMO root |
| Second enroll returns **403 `bootstrap_credential_reused`** | onboarding is genuinely one-time |
| Renew returns 200 with a 168h lifetime | one code path serves Methods A and B; only the parameter differs |

Ending with `MILESTONE 1 PASSED` means the identity layer is complete and running.

## 3B.8 File check

```bash
cd ~/pqc-xapp-auth && for f in build/Dockerfile:6 build/render.sh:8 ca/k8s/ric-ca.yaml:84 build/verify-ca.sh:54; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `build/Dockerfile` | 6 |
| `build/render.sh` | 8 |
| `ca/k8s/ric-ca.yaml` | 84 |
| `build/verify-ca.sh` | 54 |


Next: `chunk-04-keycloak.md`.
