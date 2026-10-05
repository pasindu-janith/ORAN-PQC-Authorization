# Chunk 4 - Keycloak and the first bound token

> Part of the hand-build guide for the post-quantum xApp authorization framework.
> Run the commands in order. Each chunk ends with a check that must pass before the
> next one starts. Nothing here is automated: you type it, you verify it.


**Goal:** an authorization server configured for mTLS, and a token containing
`cnf.x5t#S256`. This is the single most important check in the whole build.

**Needs the cluster?** Yes.

---

## 4.1 What Keycloak has to do differently

An existing Keycloak almost certainly cannot be used as-is. Three of the four
requirements are **startup flags**, which cannot be changed at runtime:

| Setting | Why |
|---|---|
| `--https-client-auth=request` | Keycloak must *ask* for a client certificate on the TLS handshake. Without it there is no certificate to bind to. |
| `--truststore-paths=.../ric-intermediate-ca.crt` | so it trusts certificates your RIC CA issued |
| `--https-certificate-file` = the `keycloak-server` cert | so clients verify it against the same chain |
| per-client `tls.client.certificate.bound.access.tokens=true` | **this is the one that emits `cnf.x5t#S256`.** Without it you get an ordinary bearer token and the project is pointless. |

**DPoP (Method C) needs Keycloak 26.4 or newer.** An older image cannot do Method C at all.

## 4.2 The deployment decision

Inspect what you already have (read-only):

```bash
echo "=== memory ==="; free -m | head -2; echo "=== keycloak deployment ==="; kubectl -n keycloak get deploy -o wide; echo "=== image + args ==="; kubectl -n keycloak get deploy keycloak -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}{.spec.template.spec.containers[0].args}{"\n\n"}'; echo "=== anything using it? ==="; kubectl get pods -A -o wide | grep -iE 'keycloak|auth-agent|opa'
```

A Keycloak with a 512 MB heap costs roughly 700-900 MB resident. On a 4.4 GB VM running
the RIC, that is the whole decision.

| Option | Memory | Risk |
|---|---|---|
| A: new Keycloak in `ricsec`, keep the old one | highest - two JVMs | may OOM RIC pods |
| **B: new Keycloak in `ricsec`, scale the old one to 0** | net neutral | **recommended**; instantly reversible |
| C: reconfigure the existing one in place | lowest | edits a deployment you may still need; an image older than 26.4 loses Method C |

Option B, which the rest of this chunk assumes:

```bash
kubectl -n keycloak scale deploy/keycloak --replicas=0 && sleep 10 && free -m | head -2
```

Reverse at any time with `--replicas=1`.

> **Note.** If the existing deployment uses the `:latest` tag, that is itself a hazard:
> a moving tag silently changes the server under you and can lose a realm. The new
> deployment below pins `26.6.0`.

## 4.3 The deployment

The probe timeouts matter. With the 1-second default, the kubelet kills Keycloak
mid-startup on a loaded VM and you get a confusing `exit 143` crash loop.

```bash
cat > ~/pqc-xapp-auth/keycloak/k8s/keycloak.yaml <<'EOF'
# Keycloak as the OAuth 2.0 authorization server (XRF), rendered from config/env.sh.
# mTLS terminates in Keycloak itself, so the client certificate reaches the X.509
# client authenticator and the certificate-bound token logic directly.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${KEYCLOAK_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${KEYCLOAK_SERVICE}, part-of: pqc-xapp-auth}
spec:
  replicas: 1
  strategy: {type: Recreate}
  selector:
    matchLabels: {app: ${KEYCLOAK_SERVICE}}
  template:
    metadata:
      labels: {app: ${KEYCLOAK_SERVICE}, part-of: pqc-xapp-auth}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: keycloak
          image: ${KEYCLOAK_IMAGE}
          imagePullPolicy: IfNotPresent
          args:
            - start
              # mTLS: 'request' (not 'required') so a missing or
            # untrusted certificate surfaces as a diagnosable OAuth error instead of a
            # failed handshake.
            - --https-client-auth=request
            - --truststore-paths=/etc/ric-trust/ric-intermediate-ca.crt
            - --https-protocols=TLSv1.3
            - --https-certificate-file=/etc/x509/https/tls.crt
            - --https-certificate-key-file=/etc/x509/https/tls.key
            - --https-port=${KEYCLOAK_PORT}
            - --http-enabled=false
            - --hostname=${KEYCLOAK_URL}
            - --health-enabled=true
            - --db=dev-file
            - --cache=local   # single node: no JGroups cluster
          env:
            - name: KC_BOOTSTRAP_ADMIN_USERNAME
              valueFrom: {secretKeyRef: {name: keycloak-admin, key: username}}
            - name: KC_BOOTSTRAP_ADMIN_PASSWORD
              valueFrom: {secretKeyRef: {name: keycloak-admin, key: password}}
            - {name: JAVA_OPTS_KC_HEAP, value: "${KEYCLOAK_HEAP}"}
          ports:
            - {name: https, containerPort: ${KEYCLOAK_PORT}}
            - {name: management, containerPort: 9000}
          volumeMounts:
            - {name: tls, mountPath: /etc/x509/https, readOnly: true}
            - {name: trust, mountPath: /etc/ric-trust, readOnly: true}
            - {name: data, mountPath: /opt/keycloak/data/h2}
          # Generous timeouts: on a small lab VM the JVM can stall for seconds under load,
          # and the 1s default makes the kubelet kill a healthy Keycloak.
          startupProbe:
            httpGet: {path: /health/ready, port: management, scheme: HTTPS}
            periodSeconds: 10
            timeoutSeconds: 10
            failureThreshold: 90
          readinessProbe:
            httpGet: {path: /health/ready, port: management, scheme: HTTPS}
            periodSeconds: 15
            timeoutSeconds: 10
            failureThreshold: 4
          livenessProbe:
            httpGet: {path: /health/live, port: management, scheme: HTTPS}
            periodSeconds: 30
            timeoutSeconds: 15
            failureThreshold: 10
          resources:
            requests: {cpu: 250m, memory: 600Mi}
            limits: {memory: 1Gi}
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
      volumes:
        - name: tls
          secret: {secretName: keycloak-tls}
        - name: trust
          configMap: {name: ric-trust}
        - name: data   # emptyDir: a new pod needs build/import-realm.sh run again
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ${KEYCLOAK_SERVICE}
  namespace: ${RICSEC_NAMESPACE}
  labels: {app: ${KEYCLOAK_SERVICE}, part-of: pqc-xapp-auth}
spec:
  selector: {app: ${KEYCLOAK_SERVICE}}
  ports:
    - {name: https, port: ${KEYCLOAK_PORT}, targetPort: https}
EOF
```


## 4.4 Secrets and deploy

The admin password must have **no trailing newline** - a stray newline produces an
`invalid_grant` that is painful to diagnose:

```bash
cd ~/pqc-xapp-auth && mkdir -p out/secrets && (umask 077; openssl rand -hex 16 | tr -d '\n' > out/secrets/keycloak-admin-password) && wc -c out/secrets/keycloak-admin-password
```

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create secret generic keycloak-admin --from-literal=username=admin --from-file=password=out/secrets/keycloak-admin-password
```

```bash
cd ~/pqc-xapp-auth && kubectl -n ricsec create secret tls keycloak-tls --cert=out/pki/keycloak-server-chain.crt --key=out/pki/keycloak-server.key
```

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; build/render.sh keycloak/k8s/keycloak.yaml | kubectl apply -f -
```

This pulls about 450 MB and the JVM takes a while on a small box:

```bash
kubectl -n ricsec rollout status deploy/keycloak --timeout=900s && kubectl -n ricsec get pods
```

## 4.5 The realm

Four clients. The `attributes` block of each is where the mechanism is configured.
**Methods A and B have byte-identical client configuration** - the only difference
lives in the client library. `xapp-unbound-probe` has both binding attributes false, so
the test suite can prove the validator rejects an unbound bearer token.

```bash
cat > ~/pqc-xapp-auth/keycloak/ric-realm.json <<'EOF'
{
  "realm": "${KEYCLOAK_REALM}",
  "displayName": "O-RAN Near-RT RIC xApp Authorization (XRF)",
  "enabled": true,
  "sslRequired": "all",
  "accessTokenLifespan": ${ACCESS_TOKEN_LIFESPAN},
  "roles": {
    "realm": [
      {
        "name": "${REQUIRED_ROLE}",
        "description": "Permission to call the SDL-backed resource APIs exposed by xApps"
      }
    ]
  },
  "clientScopes": [
    {
      "name": "${TOKEN_SCOPE}",
      "description": "Access to xApp SDL resources; adds the resource audience and realm roles to access tokens",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "false"
      },
      "protocolMappers": [
        {
          "name": "audience-${TOKEN_AUDIENCE}",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "consentRequired": false,
          "config": {
            "included.custom.audience": "${TOKEN_AUDIENCE}",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false"
          }
        },
        {
          "name": "realm-roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "consentRequired": false,
          "config": {
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false"
          }
        },
        {
          "name": "subject",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-sub-mapper",
          "consentRequired": false,
          "config": {
            "access.token.claim": "true",
            "introspection.token.claim": "true"
          }
        },
        {
          "name": "client-id",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usersessionmodel-note-mapper",
          "consentRequired": false,
          "config": {
            "user.session.note": "client_id",
            "claim.name": "client_id",
            "jsonType.label": "String",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
            "id.token.claim": "false"
          }
        }
      ]
    }
  ],
  "clients": [
    {
      "clientId": "${XAPP_A_CLIENT_ID}",
      "name": "Method A - RFC 8705 certificate-bound, long-term identity key",
      "description": "Identical configuration to ${XAPP_B_CLIENT_ID}; only the certificate lifetime differs (client side).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=${XAPP_A_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "true",
        "dpop.bound.access.tokens": "false"
      }
    },
    {
      "clientId": "${XAPP_B_CLIENT_ID}",
      "name": "Method B - RFC 8705 certificate-bound, ephemeral identity key",
      "description": "Identical configuration to ${XAPP_A_CLIENT_ID}; only the certificate lifetime differs (client side).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=${XAPP_B_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "true",
        "dpop.bound.access.tokens": "false"
      }
    },
    {
      "clientId": "xapp-dpop",
      "name": "Method C - RFC 9449 DPoP-bound",
      "description": "Client authentication over mTLS; the access token is bound to the client's DPoP JWK (cnf.jkt).",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=xapp-dpop,OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "dpop.bound.access.tokens": "true"
      }
    },
    {
      "clientId": "xapp-unbound-probe",
      "name": "Test only - issues plain bearer tokens (no cnf)",
      "description": "Exists solely so the test suite can prove the resource validator rejects tokens without a confirmation claim.",
      "enabled": true,
      "protocol": "openid-connect",
      "publicClient": false,
      "standardFlowEnabled": false,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": true,
      "clientAuthenticatorType": "client-x509",
      "fullScopeAllowed": true,
      "defaultClientScopes": ["${TOKEN_SCOPE}"],
      "optionalClientScopes": [],
      "attributes": {
        "x509.subjectdn": "CN=xapp-unbound-probe,OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "dpop.bound.access.tokens": "false"
      }
    }
  ],
  "users": [
    {"username": "service-account-${XAPP_A_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${XAPP_A_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-${XAPP_B_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${XAPP_B_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-dpop", "enabled": true, "serviceAccountClientId": "xapp-dpop", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-unbound-probe", "enabled": true, "serviceAccountClientId": "xapp-unbound-probe", "realmRoles": ["${REQUIRED_ROLE}"]}
  ]
}
EOF
```


## 4.6 Import the realm

```bash
which jq || sudo apt-get install -y jq
```

```bash
cat > ~/pqc-xapp-auth/build/import-realm.sh <<'EOF'
#!/usr/bin/env bash
# import-realm.sh <rendered-realm.json>
# Creates (or, with REPLACE=1, recreates) the realm through the admin REST API.
set -euo pipefail
cd "$(dirname "$0")/.."
REALM_FILE=${1:?usage: import-realm.sh <realm.json>}
: "${KEYCLOAK_URL:?source config/env.sh first}" "${KEYCLOAK_REALM:?}"

HP=${KEYCLOAK_URL#https://}; HOST=${HP%%:*}; PORT=${HP##*:}
IP=$(kubectl -n "$RICSEC_NAMESPACE" get svc "$KEYCLOAK_SERVICE" -o jsonpath='{.spec.clusterIP}')
[[ -n "$IP" ]] || { echo "no ClusterIP for $KEYCLOAK_SERVICE"; exit 1; }
CURL=(curl -sS --tlsv1.3 --resolve "${HOST}:${PORT}:${IP}" --cacert out/pki/ric-intermediate-ca.crt)

# password@file sends the file content byte-for-byte, exactly as the Secret holds it
TOKEN=$("${CURL[@]}" -d grant_type=password -d client_id=admin-cli -d username=admin \
  --data-urlencode "password@out/secrets/keycloak-admin-password" \
  "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" | jq -r .access_token)
[[ -n "$TOKEN" && "$TOKEN" != null ]] || { echo "could not obtain admin token"; exit 1; }
AUTH=(-H "Authorization: Bearer $TOKEN")

exists=$("${CURL[@]}" "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM")
if [[ "$exists" == 200 ]]; then
  if [[ "${REPLACE:-0}" != 1 ]]; then
    echo "realm $KEYCLOAK_REALM already exists (REPLACE=1 to recreate)"
    exit 0
  fi
  "${CURL[@]}" "${AUTH[@]}" -X DELETE "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM"
fi

code=$("${CURL[@]}" "${AUTH[@]}" -H 'Content-Type: application/json' --data-binary @"$REALM_FILE" \
  -o /tmp/import-realm.out -w '%{http_code}' "$KEYCLOAK_URL/admin/realms")
[[ "$code" == 201 ]] || { echo "realm import failed: HTTP $code $(cat /tmp/import-realm.out)"; exit 1; }
echo "realm $KEYCLOAK_REALM imported"
EOF
```


```bash
chmod +x ~/pqc-xapp-auth/build/import-realm.sh
```

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; mkdir -p out/rendered && build/render.sh keycloak/ric-realm.json > out/rendered/ric-realm.json && build/import-realm.sh out/rendered/ric-realm.json
```

Because the H2 database is an `emptyDir`, **if the Keycloak pod restarts you must
re-run this import**. It is idempotent.

## 4.7 Milestone 2

```bash
cat > ~/pqc-xapp-auth/build/verify-keycloak.sh <<'EOF'
#!/usr/bin/env bash
# Milestone 2: a token requested over mTLS must carry cnf.x5t#S256 equal to the
# SHA-256 thumbprint of the certificate presented. Keycloak issues a token even when
# the certificate never reaches it, so a missing cnf is a FAILURE, not a warning.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${KEYCLOAK_URL:?source config/env.sh first}"

PKI=out/pki
CLIENT=${XAPP_A_CLIENT_ID}
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

ip_of() { kubectl -n "$1" get svc "$2" -o jsonpath='{.spec.clusterIP}'; }
KC_RESOLVE="${KEYCLOAK_HOST}:${KEYCLOAK_PORT}:$(ip_of "$RICSEC_NAMESPACE" "$KEYCLOAK_SERVICE")"
CA_RESOLVE="${RIC_CA_HOST}:${RIC_CA_PORT}:$(ip_of "$RICSEC_NAMESPACE" "$RIC_CA_SERVICE")"
TOKEN_URL="${TOKEN_ISSUER}/protocol/openid-connect/token"

b64url_json() { local s=${1//-/+}; s=${s//_//}; while (( ${#s} % 4 )); do s+="="; done; base64 -d <<<"$s"; }
thumbprint() { openssl x509 -in "$1" -outform der | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='; }

echo "==> Onboard and enroll '$CLIENT'"
out/bin/smo-sim -cn "$CLIENT" -validity 10m -out "$WORK/boot" -org "$ORG" \
  -ca-cert "$PKI/smo-onboarding-ca.crt" -ca-key "$PKI/smo-onboarding-ca.key" >/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/op.key" 2>/dev/null
openssl req -new -key "$WORK/op.key" -subj "/CN=$CLIENT" -out "$WORK/op.csr"
code=$(curl -sS --tlsv1.3 --resolve "$CA_RESOLVE" --cacert "$PKI/ric-intermediate-ca.crt" \
  --cert "$WORK/boot/tls.crt" --key "$WORK/boot/tls.key" --data-binary @"$WORK/op.csr" \
  -o "$WORK/op.crt" -w '%{http_code}' "$RIC_CA_URL/v1/enroll?lifetime=$LONGTERM_CERT_LIFETIME")
[[ "$code" == 200 ]] || { echo "FAIL: enrollment $code $(cat "$WORK/op.crt")"; exit 1; }
openssl x509 -in "$WORK/op.crt" -noout -subject

token_request() {
  rm -f "$WORK/resp.json"
  curl -sS --tlsv1.3 --resolve "$KC_RESOLVE" --cacert "$PKI/ric-intermediate-ca.crt" "$@" \
    -d grant_type=client_credentials -d client_id="$CLIENT" -d scope="$TOKEN_SCOPE" \
    -o "$WORK/resp.json" -w '%{http_code}' "$TOKEN_URL" 2>"$WORK/curl.err" || true
}

echo "==> Token request over mTLS with the operational certificate"
code=$(token_request --cert "$WORK/op.crt" --key "$WORK/op.key")
[[ "$code" == 200 ]] || { echo "FAIL: token endpoint returned $code: $(cat "$WORK/resp.json")"; exit 1; }
TOKEN=$(jq -r .access_token "$WORK/resp.json")
PAYLOAD=$(b64url_json "$(cut -d. -f2 <<<"$TOKEN")")
echo "token_type=$(jq -r .token_type "$WORK/resp.json") bytes=${#TOKEN}"
jq '{iss, aud, azp, client_id, scope, realm_access, exp, cnf}' <<<"$PAYLOAD"

CNF=$(jq -r '.cnf["x5t#S256"] // empty' <<<"$PAYLOAD")
EXPECTED=$(thumbprint "$WORK/op.crt")
[[ -n "$CNF" ]] || { echo "FAIL: cnf.x5t#S256 absent - the certificate did not reach Keycloak (token issued anyway)"; exit 1; }
[[ "$CNF" == "$EXPECTED" ]] || { echo "FAIL: cnf=$CNF but thumbprint=$EXPECTED"; exit 1; }
echo "OK: cnf.x5t#S256 == SHA-256 thumbprint of the presented certificate ($EXPECTED)"

echo "==> No client certificate must not yield a token"
code=$(token_request); echo "HTTP $code $(cat "$WORK/resp.json" 2>/dev/null)"
[[ "$code" != 200 ]] || { echo "FAIL: token issued without a client certificate"; exit 1; }

echo "==> A certificate outside the RIC trust anchor must not yield a token"
code=$(token_request --cert "$WORK/boot/tls.crt" --key "$WORK/boot/tls.key")
echo "HTTP $code $(cat "$WORK/resp.json" 2>/dev/null)"
[[ "$code" != 200 ]] || { echo "FAIL: token issued for an untrusted certificate"; exit 1; }

echo
echo "MILESTONE 2 PASSED"
EOF
```


```bash
chmod +x ~/pqc-xapp-auth/build/verify-keycloak.sh
```

```bash
cd ~/pqc-xapp-auth && set -a; source config/env.sh; set +a; build/verify-keycloak.sh
```

**If `cnf.x5t#S256` is present and equals your certificate thumbprint,
sender-constraining works and everything afterwards is enforcement. If `cnf` is absent,
Keycloak issued a plain bearer token and nothing downstream is meaningful.**

Expected output includes:

```json
"cnf": { "x5t#S256": "<base64url SHA-256 of the certificate you presented>" }
```

Two results that look like errors but are not:

- The no-certificate test returning **HTTP 401 `invalid_client`** is correct.
- The untrusted-certificate test returning **HTTP 000** is *stronger* than a 401: `000`
  means curl never completed the TLS handshake, so the Keycloak truststore rejected the
  certificate at the TLS layer and the request never reached the OAuth endpoint.

## 4.8 File check

```bash
cd ~/pqc-xapp-auth && for f in keycloak/k8s/keycloak.yaml:97 keycloak/ric-realm.json:175 build/import-realm.sh:33 build/verify-keycloak.sh:63; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-34s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `keycloak/k8s/keycloak.yaml` | 97 |
| `keycloak/ric-realm.json` | 175 |
| `build/import-realm.sh` | 33 |
| `build/verify-keycloak.sh` | 63 |


Next: `chunk-05a-client-foundations.md`.
