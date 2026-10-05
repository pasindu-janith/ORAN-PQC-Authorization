# Chunk 10B - Kyverno, ChartMuseum and dms_cli

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


**Goal:** two xApps onboarded the way an operator would, running a stock BusyBox
image, with the sidecar added at admission time and all their HTTP and RMR traffic
authorized over the post-quantum tunnel.

**Needs the cluster?** Yes, plus three node-level services.

**Requires `PQ_MODE=true`** - `sidecar.New` refuses to start otherwise, because the
tunnel authenticates peers with ML-DSA certificates.

---

## What this chunk is actually demonstrating

The descriptors you hand `dms_cli` declare **one** container and contain no security
code and no security configuration - only five annotations. Two containers run. That
is the claim: sender-constrained, post-quantum authorization added to an unmodified
xApp by the platform, not by the xApp.

## 10B.1 Node prerequisites

```bash
for c in helm dms_cli chartmuseum docker; do printf '%-12s %s\n' "$c" "$(command -v $c || echo MISSING)"; done; echo "--- registry ---"; curl -sS --max-time 3 http://127.0.0.1:5000/v2/_catalog || echo "no registry on :5000"; echo; echo "--- chartmuseum ---"; curl -sS --max-time 3 http://localhost:8090/health || echo "no chartmuseum on :8090"
```

**Local registry** - `dms_cli` requires a registry host in the descriptor:

```bash
sudo docker ps -a --filter name=local-registry --format '{{.Names}} {{.Status}}' | grep . || sudo docker run -d --restart=always -p 5000:5000 --name local-registry registry:2
```

```bash
sudo docker start local-registry 2>/dev/null; sleep 2; curl -s http://127.0.0.1:5000/v2/_catalog
```

**ChartMuseum** - `dms_cli` pushes the chart it builds to `CHART_REPO_URL`. The binary
ships with the RIC install but is not started by it:

```bash
command -v chartmuseum || { curl -sL https://get.helm.sh/chartmuseum-v0.16.1-linux-amd64.tar.gz -o /tmp/cm.tgz && tar -xzf /tmp/cm.tgz -C /tmp && sudo install -m 0755 /tmp/linux-amd64/chartmuseum /usr/local/bin/chartmuseum; }
```

```bash
mkdir -p ~/chartstorage && printf '[Unit]\nDescription=ChartMuseum local Helm chart repository\nAfter=network.target\n\n[Service]\nUser=%s\nEnvironment=STORAGE=local\nEnvironment=STORAGE_LOCAL_ROOTDIR=%s/chartstorage\nEnvironment=PORT=8090\nEnvironment=ALLOW_OVERWRITE=true\nExecStart=/usr/local/bin/chartmuseum\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n' "$USER" "$HOME" | sudo tee /etc/systemd/system/chartmuseum.service >/dev/null && sudo systemctl daemon-reload && sudo systemctl enable --now chartmuseum && sleep 4 && curl -s localhost:8090/health; echo
```

Expected: `{"healthy":true}`. **Do not continue until you see it** - `dms_cli onboard`
fails obscurely when nothing is listening. If the service does not come up:

```bash
sudo systemctl status chartmuseum --no-pager -l | head -20; sudo journalctl -u chartmuseum --no-pager -n 25
```

Some builds want flags rather than environment variables:

```bash
sudo sed -i "s|^ExecStart=.*|ExecStart=/usr/local/bin/chartmuseum --port=8090 --storage=local --storage-local-rootdir=$HOME/chartstorage --allow-overwrite|" /etc/systemd/system/chartmuseum.service && sudo systemctl daemon-reload && sudo systemctl restart chartmuseum && sleep 4 && curl -s localhost:8090/health; echo
```

**`dms_cli`** - installed by the RIC deployment; install directly if missing:

```bash
command -v dms_cli || { git clone https://gerrit.o-ran-sc.org/r/it/dev ~/it-dev && sudo pip3 install ~/it-dev/xapp_onboarder; }
```

## 10B.2 Two more Keycloak clients

The realm needs `xapp-sidecar-c` (certificate-bound, Method A) and `xapp-sidecar-d`
(DPoP-bound, Method C). **`keycloak/ric-realm.json` in Chunk 4 already contains all
six clients** - if you built from an earlier version that had four, replace the whole
file rather than splicing JSON:

```bash
cat > ~/pqc-xapp-auth/keycloak/ric-realm.json <<'KEYCLOAK_RIC_REALM_JSON_EOF'
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
      "clientId": "${SIDECAR_C_CLIENT_ID}",
      "name": "Sidecar xApp C - certificate-bound over the post-quantum tunnel",
      "description": "Onboarded with dms_cli; the sidecar injected by Kyverno holds this identity. The token is bound to the ML-DSA certificate that authenticates the tunnel handshake.",
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
        "x509.subjectdn": "CN=${SIDECAR_C_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "true",
        "dpop.bound.access.tokens": "false"
      }
    },
    {
      "clientId": "${SIDECAR_D_CLIENT_ID}",
      "name": "Sidecar xApp D - DPoP-bound over the post-quantum tunnel",
      "description": "Onboarded with dms_cli; the sidecar proves possession of the ML-DSA proof key that cnf.jkt names when it opens a tunnel.",
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
        "x509.subjectdn": "CN=${SIDECAR_D_CLIENT_ID},OU=${XAPP_OU},O=${ORG}",
        "x509.allow.regex.pattern.comparison": "false",
        "tls.client.certificate.bound.access.tokens": "false",
        "dpop.bound.access.tokens": "true"
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
    {"username": "service-account-${SIDECAR_C_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${SIDECAR_C_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-${SIDECAR_D_CLIENT_ID}", "enabled": true, "serviceAccountClientId": "${SIDECAR_D_CLIENT_ID}", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-dpop", "enabled": true, "serviceAccountClientId": "xapp-dpop", "realmRoles": ["${REQUIRED_ROLE}"]},
    {"username": "service-account-xapp-unbound-probe", "enabled": true, "serviceAccountClientId": "xapp-unbound-probe", "realmRoles": ["${REQUIRED_ROLE}"]}
  ]
}
KEYCLOAK_RIC_REALM_JSON_EOF
```


Validate the render **before** touching Keycloak:

```bash
cd ~/pqc-xapp-auth && wc -l keycloak/ric-realm.json && set -a && source config/env.sh && set +a && build/render.sh keycloak/ric-realm.json > /tmp/realm.json && python3 -c "import json;d=json.load(open('/tmp/realm.json'));print(len(d['clients']),'clients:',[c['clientId'] for c in d['clients']]);print(len(d['users']),'users')"
```

Expected: **221** lines, then

```
6 clients: ['xapp-longterm', 'xapp-ephemeral', 'xapp-sidecar-c', 'xapp-sidecar-d', 'xapp-dpop', 'xapp-unbound-probe']
6 users
```

> **`import-realm.sh` with `REPLACE=1` deletes the realm before it imports.** If the
> JSON is malformed the delete still happens and the import fails, leaving no realm at
> all - `xapp-a`, `xapp-b` and the shim all stop getting tokens until you fix it. Never
> run it without the `json.load` check above passing first.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && REPLACE=1 build/import-realm.sh /tmp/realm.json
```

Expected: `realm ric-realm imported`. Confirm the rest of the deployment recovered:

```bash
cd ~/pqc-xapp-auth && ./scripts/run-method-a.sh --pq 2>&1 | tail -8
```

Must still end with **All checks passed.**

## 10B.3 Images

The sidecar binary, into the same scratch image the other components use:

```bash
cd ~/pqc-xapp-auth && CGO_ENABLED=0 go build -p=2 -o out/bin/ ./sidecar/cmd/xapp-sidecar && set -a && source config/env.sh && set +a && sudo docker build -q --build-arg BIN=xapp-sidecar -t "ricsec/xapp-sidecar:${IMAGE_TAG}" -f build/Dockerfile out/bin && sudo docker save "ricsec/xapp-sidecar:${IMAGE_TAG}" | sudo ctr -n k8s.io images import - && sudo ctr -n k8s.io images ls -q | grep xapp-sidecar
```

The demo app image - plain BusyBox, pushed to the local registry. **It contains no
security code whatsoever**, which is the point:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && sudo docker pull "busybox:${DEMO_APP_IMAGE_TAG}" && sudo docker tag "busybox:${DEMO_APP_IMAGE_TAG}" "${LOCAL_REGISTRY}/${DEMO_APP_IMAGE_NAME}:${DEMO_APP_IMAGE_TAG}" && sudo docker push "${LOCAL_REGISTRY}/${DEMO_APP_IMAGE_NAME}:${DEMO_APP_IMAGE_TAG}"
```

## 10B.4 Kyverno

Only the admission controller: this testbed uses one mutation rule on pod creation and
none of the background, reports or cleanup controllers, and the lab node has little
memory to spare.

```bash
cat > ~/pqc-xapp-auth/scripts/install-kyverno.sh <<'SCRIPTS_INSTALL_KYVERNO_SH_EOF'
#!/usr/bin/env bash
# Installs the Kyverno admission controller, which is what injects the sidecar.
#
# Only the admission controller is installed: this testbed uses one mutation rule on
# pod creation and none of the background, reports or cleanup controllers, and the
# lab node has little memory to spare.
set -euo pipefail
CHART_VERSION=${KYVERNO_CHART_VERSION:-3.3.9}

if kubectl get deploy -n kyverno kyverno-admission-controller >/dev/null 2>&1; then
  echo "kyverno already installed:"
  kubectl -n kyverno get deploy kyverno-admission-controller
  exit 0
fi

helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null
helm repo update kyverno >/dev/null
helm install kyverno kyverno/kyverno \
  --version "$CHART_VERSION" \
  --namespace kyverno --create-namespace \
  --set admissionController.replicas=1 \
  --set admissionController.container.resources.requests.cpu=100m \
  --set admissionController.container.resources.requests.memory=128Mi \
  --set admissionController.container.resources.limits.memory=384Mi \
  --set backgroundController.enabled=false \
  --set reportsController.enabled=false \
  --set cleanupController.enabled=false \
  --set crds.migration.enabled=false \
  --timeout 10m --wait

kubectl -n kyverno get pods
SCRIPTS_INSTALL_KYVERNO_SH_EOF
```


```bash
chmod +x ~/pqc-xapp-auth/scripts/install-kyverno.sh
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && scripts/install-kyverno.sh
```

This pulls a chart and waits for the webhook; allow a few minutes.

## 10B.5 The injection policy and the sidecar Services

```bash
cat > ~/pqc-xapp-auth/deploy/kyverno/sidecar-policy.yaml <<'KYVERNO_SIDECAR_POLICY_YAML_EOF'
# Kyverno injects the token-binding sidecar into any xApp pod that asks for it with
# annotations. The xApp image, the xApp source and the xApp descriptor containers
# section stay untouched; the descriptor only carries the annotations below, which
# dms_cli passes straight through to the pod template.
#
#   pq.oran/inject     "true"
#   pq.oran/client-id  the OAuth client id, which is also the certificate CN and the
#                      name of the bootstrap secrets (<id>-bootstrap, <id>-bootstrap-pq)
#   pq.oran/method     A, B or C
#   pq.oran/ingress    route|localAddr[,route|localAddr...]
#   pq.oran/egress     route|listenAddr|peerHost:port|peerName[,...]
#
# Everything else - issuer URLs, trust bundle, PQ settings - comes from the
# pqc-xapp-auth ConfigMap that already exists in the namespace.
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: pqc-xapp-auth-sidecar
  labels: {part-of: pqc-xapp-auth}
  annotations:
    policies.kyverno.io/title: xApp token-binding sidecar injection
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/description: >-
      Adds the post-quantum token-binding sidecar, its credentials and its trust
      anchors to annotated xApp pods, so that an unmodified xApp gets
      sender-constrained authorization on both its HTTP and its RMR traffic.
spec:
  background: false
  rules:
    - name: inject-token-binding-sidecar
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: ["${XAPP_NAMESPACE}"]
              annotations:
                pq.oran/inject: "true"
      context:
        - name: clientID
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/client-id"'
        - name: method
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/method" || ''A'''
        - name: ingressRoutes
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/ingress" || '''''
        - name: egressRoutes
          variable:
            jmesPath: 'request.object.metadata.annotations."pq.oran/egress" || '''''
      preconditions:
        all:
          - key: "{{ clientID || '' }}"
            operator: NotEquals
            value: ""
      mutate:
        patchStrategicMerge:
          metadata:
            labels:
              # The sidecar Service selects on this label, so it works whatever the
              # onboarding chart happens to call the pod.
              pq.oran/sidecar: "{{ clientID }}"
          spec:
            volumes:
              - name: pq-bootstrap
                secret:
                  secretName: "{{ clientID }}-bootstrap"
                  defaultMode: 288
              - name: pq-bootstrap-pq
                secret:
                  secretName: "{{ clientID }}-bootstrap-pq"
                  defaultMode: 288
              - name: pq-trust
                configMap:
                  name: ric-trust
              - name: pq-identity
                emptyDir: {medium: Memory}
              - name: pq-identity-pq
                emptyDir: {medium: Memory}
            containers:
              - name: pq-sidecar
                image: ${SIDECAR_IMAGE}
                imagePullPolicy: ${SIDECAR_PULL_POLICY}
                envFrom:
                  - configMapRef: {name: pqc-xapp-auth}
                env:
                  - {name: SIDECAR_NAME, value: "{{ clientID }}"}
                  - {name: XAPP_CLIENT_ID, value: "{{ clientID }}"}
                  - {name: XAPP_METHOD, value: "{{ method }}"}
                  - {name: SIDECAR_AUTHORITY, value: "{{ clientID }}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}"}
                  - {name: SIDECAR_INGRESS_LISTEN, value: ":${SIDECAR_PORT}"}
                  - {name: SIDECAR_INGRESS_ROUTES, value: "{{ ingressRoutes }}"}
                  - {name: SIDECAR_EGRESS_ROUTES, value: "{{ egressRoutes }}"}
                  - {name: SIDECAR_HEALTH_LISTEN, value: ":${SIDECAR_HEALTH_PORT}"}
                ports:
                  - {name: pq-tunnel, containerPort: ${SIDECAR_PORT}}
                  - {name: pq-health, containerPort: ${SIDECAR_HEALTH_PORT}}
                readinessProbe:
                  httpGet: {path: /healthz, port: pq-health, scheme: HTTP}
                  initialDelaySeconds: 5
                  periodSeconds: 10
                  timeoutSeconds: 5
                  failureThreshold: 12
                volumeMounts:
                  - {name: pq-bootstrap, mountPath: /etc/xapp/bootstrap, readOnly: true}
                  - {name: pq-bootstrap-pq, mountPath: /etc/xapp/bootstrap-pq, readOnly: true}
                  - {name: pq-trust, mountPath: /etc/ric-trust, readOnly: true}
                  - {name: pq-identity, mountPath: /var/run/xapp/identity}
                  - {name: pq-identity-pq, mountPath: /var/run/xapp/identity-pq}
                resources:
                  requests: {cpu: 20m, memory: 32Mi}
                  limits: {memory: 128Mi}
                securityContext:
                  runAsNonRoot: true
                  runAsUser: 65532
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                  capabilities: {drop: [ALL]}
KYVERNO_SIDECAR_POLICY_YAML_EOF
```


```bash
cat > ~/pqc-xapp-auth/deploy/kyverno/sidecar-services.yaml <<'KYVERNO_SIDECAR_SERVICES_YAML_EOF'
# One Service per onboarded xApp, pointing at the injected sidecar rather than at the
# application. It selects on the label the Kyverno policy adds, so it works whatever
# the onboarding chart names the pod, and it publishes only the tunnel port: the
# application ports are never exposed outside the pod.
apiVersion: v1
kind: Service
metadata:
  name: ${SIDECAR_C_CLIENT_ID}-sidecar
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: pqc-xapp-auth}
spec:
  selector:
    pq.oran/sidecar: ${SIDECAR_C_CLIENT_ID}
  ports:
    - {name: pq-tunnel, port: ${SIDECAR_PORT}, targetPort: pq-tunnel}
---
apiVersion: v1
kind: Service
metadata:
  name: ${SIDECAR_D_CLIENT_ID}-sidecar
  namespace: ${XAPP_NAMESPACE}
  labels: {part-of: pqc-xapp-auth}
spec:
  selector:
    pq.oran/sidecar: ${SIDECAR_D_CLIENT_ID}
  ports:
    - {name: pq-tunnel, port: ${SIDECAR_PORT}, targetPort: pq-tunnel}
KYVERNO_SIDECAR_SERVICES_YAML_EOF
```


Check the render. The `{{ clientID }}` placeholders are Kyverno's own and **must**
survive - only `${...}` matters:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for f in deploy/kyverno/sidecar-policy.yaml deploy/kyverno/sidecar-services.yaml; do echo "== $f"; build/render.sh $f | grep -n '\${' && echo "  UNSUBSTITUTED - stop" || echo "  clean"; done
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && build/render.sh deploy/kyverno/sidecar-policy.yaml | kubectl apply -f - && build/render.sh deploy/kyverno/sidecar-services.yaml | kubectl apply -f - && kubectl wait --for=condition=Ready clusterpolicy/pqc-xapp-auth-sidecar --timeout=60s
```

## 10B.6 Bootstrap credentials for the two sidecar xApps

The client id doubles as the deployment name, and the Service name adds a `-sidecar`
suffix, so the certificate carries both:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && export SMO_ONBOARDING_CERT="$PWD/out/pki/smo-onboarding-ca.crt" SMO_ONBOARDING_KEY="$PWD/out/pki/smo-onboarding-ca.key" && for cid in "$SIDECAR_C_CLIENT_ID" "$SIDECAR_D_CLIENT_ID"; do dns="$cid.$XAPP_NAMESPACE.svc.$CLUSTER_DOMAIN,$cid.$XAPP_NAMESPACE.svc,$cid-sidecar.$XAPP_NAMESPACE.svc.$CLUSTER_DOMAIN,$cid-sidecar.$XAPP_NAMESPACE.svc"; rm -rf "out/bootstrap/$cid" "out/bootstrap/$cid-pq"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$cid" -validity "$BOOTSTRAP_CERT_VALIDITY"; out/bin/smo-sim -cn "$cid" -dns "$dns" -out "out/bootstrap/$cid-pq" -validity "$BOOTSTRAP_CERT_VALIDITY" -key-alg "$PQ_IDENTITY_KEY_ALG" -ca-cert "$PWD/out/pki/smo-onboarding-ca-pq.crt" -ca-key "$PWD/out/pki/smo-onboarding-ca-pq.key"; done
```

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for cid in "$SIDECAR_C_CLIENT_ID" "$SIDECAR_D_CLIENT_ID"; do for suffix in "" "-pq"; do kubectl -n "$XAPP_NAMESPACE" delete secret "${cid}-bootstrap${suffix}" --ignore-not-found; kubectl -n "$XAPP_NAMESPACE" create secret generic "${cid}-bootstrap${suffix}" --from-file=tls.crt="out/bootstrap/${cid}${suffix}/tls.crt" --from-file=tls.key="out/bootstrap/${cid}${suffix}/tls.key"; done; done
```

## 10B.7 The descriptors

What an operator writes. **Nothing here mentions the sidecar.**

```bash
cat > ~/pqc-xapp-auth/xapps/schema.json <<'XAPPS_SCHEMA_JSON_EOF'
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "http://o-ran-sc.org/pqc-xapp-auth-controls.json",
  "type": "object",
  "title": "Controls section of the token-binding demo xApps",
  "description": "These xApps carry no configuration of their own: every security parameter belongs to the sidecar, which Kyverno injects from the pod annotations.",
  "properties": {},
  "additionalProperties": false
}
XAPPS_SCHEMA_JSON_EOF
```


```bash
cat > ~/pqc-xapp-auth/xapps/xappc-config.json <<'XAPPS_XAPPC_CONFIG_JSON_EOF'
{
  "name": "${SIDECAR_C_XAPP}",
  "version": "1.0.0",
  "annotations": {
    "pq.oran/inject": "true",
    "pq.oran/client-id": "${SIDECAR_C_CLIENT_ID}",
    "pq.oran/method": "${SIDECAR_C_METHOD}",
    "pq.oran/ingress": "http|127.0.0.1:${SIDECAR_APP_HTTP_PORT},rmr|127.0.0.1:${SIDECAR_APP_RMR_PORT}",
    "pq.oran/egress": "http|127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}|${SIDECAR_D_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_D_CLIENT_ID},rmr|127.0.0.1:${SIDECAR_LOCAL_RMR_PORT}|${SIDECAR_D_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_D_CLIENT_ID}"
  },
  "containers": [
    {
      "name": "${SIDECAR_C_XAPP}",
      "image": {
        "registry": "${LOCAL_REGISTRY}",
        "name": "${DEMO_APP_IMAGE_NAME}",
        "tag": "${DEMO_APP_IMAGE_TAG}"
      },
      "command": ["/bin/sh"],
      "args": [
        "-c",
        "mkdir -p /tmp/www; echo 'hello from xappc, served over the post-quantum tunnel' > /tmp/www/index.html; httpd -p ${SIDECAR_APP_HTTP_PORT} -h /tmp/www; while true; do nc -l -p ${SIDECAR_APP_RMR_PORT} | sed 's/^/[rmr-in] /'; done & sleep 25; while true; do echo '[http-out] calling the peer xApp through the sidecar'; wget -q -T 25 -O - http://127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}/ | sed 's/^/[http-in] /'; echo '[rmr-out] sending an RMR message through the sidecar'; echo 'RMR:xappc:hello' | nc -w 10 127.0.0.1 ${SIDECAR_LOCAL_RMR_PORT}; sleep 15; done"
      ]
    }
  ],
  "messaging": {
    "ports": [
      {
        "name": "http",
        "container": "${SIDECAR_C_XAPP}",
        "port": ${SIDECAR_APP_HTTP_PORT},
        "description": "application HTTP port, reachable only through the sidecar"
      },
      {
        "name": "rmr-data",
        "container": "${SIDECAR_C_XAPP}",
        "port": ${SIDECAR_APP_RMR_PORT},
        "description": "RMR data port, reachable only through the sidecar"
      }
    ]
  },
  "controls": {}
}
XAPPS_XAPPC_CONFIG_JSON_EOF
```


```bash
cat > ~/pqc-xapp-auth/xapps/xappd-config.json <<'XAPPS_XAPPD_CONFIG_JSON_EOF'
{
  "name": "${SIDECAR_D_XAPP}",
  "version": "1.0.0",
  "annotations": {
    "pq.oran/inject": "true",
    "pq.oran/client-id": "${SIDECAR_D_CLIENT_ID}",
    "pq.oran/method": "${SIDECAR_D_METHOD}",
    "pq.oran/ingress": "http|127.0.0.1:${SIDECAR_APP_HTTP_PORT},rmr|127.0.0.1:${SIDECAR_APP_RMR_PORT}",
    "pq.oran/egress": "http|127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}|${SIDECAR_C_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_C_CLIENT_ID},rmr|127.0.0.1:${SIDECAR_LOCAL_RMR_PORT}|${SIDECAR_C_CLIENT_ID}-sidecar.${XAPP_NAMESPACE}.svc.${CLUSTER_DOMAIN}:${SIDECAR_PORT}|${SIDECAR_C_CLIENT_ID}"
  },
  "containers": [
    {
      "name": "${SIDECAR_D_XAPP}",
      "image": {
        "registry": "${LOCAL_REGISTRY}",
        "name": "${DEMO_APP_IMAGE_NAME}",
        "tag": "${DEMO_APP_IMAGE_TAG}"
      },
      "command": ["/bin/sh"],
      "args": [
        "-c",
        "mkdir -p /tmp/www; echo 'hello from xappd, served over the post-quantum tunnel' > /tmp/www/index.html; httpd -p ${SIDECAR_APP_HTTP_PORT} -h /tmp/www; while true; do nc -l -p ${SIDECAR_APP_RMR_PORT} | sed 's/^/[rmr-in] /'; done & sleep 25; while true; do echo '[http-out] calling the peer xApp through the sidecar'; wget -q -T 25 -O - http://127.0.0.1:${SIDECAR_LOCAL_HTTP_PORT}/ | sed 's/^/[http-in] /'; echo '[rmr-out] sending an RMR message through the sidecar'; echo 'RMR:xappd:hello' | nc -w 10 127.0.0.1 ${SIDECAR_LOCAL_RMR_PORT}; sleep 15; done"
      ]
    }
  ],
  "messaging": {
    "ports": [
      {
        "name": "http",
        "container": "${SIDECAR_D_XAPP}",
        "port": ${SIDECAR_APP_HTTP_PORT},
        "description": "application HTTP port, reachable only through the sidecar"
      },
      {
        "name": "rmr-data",
        "container": "${SIDECAR_D_XAPP}",
        "port": ${SIDECAR_APP_RMR_PORT},
        "description": "RMR data port, reachable only through the sidecar"
      }
    ]
  },
  "controls": {}
}
XAPPS_XAPPD_CONFIG_JSON_EOF
```


## 10B.8 The onboarding script

```bash
cat > ~/pqc-xapp-auth/scripts/onboard-sidecar-xapps.sh <<'SCRIPTS_ONBOARD_SIDECAR_XAPPS_SH_EOF'
#!/usr/bin/env bash
# Onboards the two sidecar demo xApps the way an operator would: render the
# descriptors, hand them to dms_cli, then install the resulting Helm charts.
#
# Nothing here mentions the sidecar. The descriptors carry annotations; Kyverno turns
# those into a container at admission time.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

: "${XAPP_NAMESPACE:?}" "${SIDECAR_C_XAPP:?}" "${SIDECAR_D_XAPP:?}" "${CHART_REPO_URL:?}"
export CHART_REPO_URL

out=out/rendered/xapps
mkdir -p "$out"
build/render.sh xapps/schema.json > "$out/schema.json"

onboard() {
  local xapp=$1 src=$2
  build/render.sh "$src" > "$out/$xapp-config.json"
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out/$xapp-config.json"
  echo "== onboarding $xapp"
  # The flag really is spelled shcema_file_path in xapp_onboarder.
  dms_cli onboard --config_file_path="$ROOT/$out/$xapp-config.json" --shcema_file_path="$ROOT/$out/schema.json"
}

install() {
  local xapp=$1
  if helm status -n "$XAPP_NAMESPACE" "$xapp" >/dev/null 2>&1; then
    echo "== removing the previous $xapp release"
    dms_cli uninstall --xapp_chart_name="$xapp" --namespace="$XAPP_NAMESPACE" || true
    # The bootstrap credential is one-time, so the old pod must be gone before the new
    # one starts; a second enrollment with the same credential is refused, by design.
    kubectl -n "$XAPP_NAMESPACE" wait --for=delete pod \
      -l "app=$XAPP_NAMESPACE-$xapp" --timeout=120s >/dev/null 2>&1 || true
  fi
  echo "== installing $xapp into $XAPP_NAMESPACE"
  dms_cli install --xapp_chart_name="$xapp" --version=1.0.0 --namespace="$XAPP_NAMESPACE"
}

onboard "$SIDECAR_C_XAPP" xapps/xappc-config.json
onboard "$SIDECAR_D_XAPP" xapps/xappd-config.json

install "$SIDECAR_C_XAPP"
install "$SIDECAR_D_XAPP"

echo
echo "onboarded xApps:"
kubectl -n "$XAPP_NAMESPACE" get pods -l 'pq.oran/sidecar' -o wide
SCRIPTS_ONBOARD_SIDECAR_XAPPS_SH_EOF
```


```bash
chmod +x ~/pqc-xapp-auth/scripts/onboard-sidecar-xapps.sh
```

## 10B.9 Check, onboard, install

```bash
cd ~/pqc-xapp-auth && for f in deploy/kyverno/sidecar-policy.yaml:118 deploy/kyverno/sidecar-services.yaml:27 scripts/install-kyverno.sh:31 scripts/onboard-sidecar-xapps.sh:49 xapps/schema.json:9 xapps/xappc-config.json:43 xapps/xappd-config.json:43 keycloak/ric-realm.json:221; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `deploy/kyverno/sidecar-policy.yaml` | 118 |
| `deploy/kyverno/sidecar-services.yaml` | 27 |
| `scripts/install-kyverno.sh` | 31 |
| `scripts/onboard-sidecar-xapps.sh` | 49 |
| `xapps/schema.json` | 9 |
| `xapps/xappc-config.json` | 43 |
| `xapps/xappd-config.json` | 43 |
| `keycloak/ric-realm.json` | 221 |


```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && scripts/onboard-sidecar-xapps.sh
```

Expected: `{"status": "Created"}` twice, then `status: OK` twice.

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_NAMESPACE-$SIDECAR_C_XAPP" --timeout=300s && kubectl -n "$XAPP_NAMESPACE" rollout status deploy/"$XAPP_NAMESPACE-$SIDECAR_D_XAPP" --timeout=300s
```

## 10B.10 Verify

**The injection happened** - two containers in a pod whose chart asked for one:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" get pods -l 'pq.oran/sidecar' -o custom-columns=POD:.metadata.name,READY:.status.containerStatuses[*].ready,CONTAINERS:.spec.containers[*].name
```

```
POD                              READY       CONTAINERS
ricxapp-xappc-...                true,true   pq-sidecar,xappc
ricxapp-xappd-...                true,true   pq-sidecar,xappd
```

**Both sidecars enrolled** with ML-DSA identities:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs -l 'pq.oran/sidecar' -c pq-sidecar --prefix --tail=60 | grep -E 'sidecar_ready|ingress_listening|egress_listening' | cut -c1-280
```

**Traffic authorized, both directions, both protocols, both bindings:**

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs -l 'pq.oran/sidecar' -c pq-sidecar --prefix --since=3m | grep -E 'egress_authorized|ingress_authorized' | cut -c1-320 | tail -12
```

Across those lines you should see `route=http` **and** `route=rmr`;
`binding=x5t#S256` from `xapp-sidecar-c` and `binding=jkt` from `xapp-sidecar-d`;
`post_quantum=true`, `token_alg=ML-DSA-65`, `peer_sig_alg=ML-DSA-65`,
`kex=ML-KEM-768`; and `handshake_ms`, which is a number for your measurements
chapter.

**The applications see each other:**

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs "deploy/$XAPP_NAMESPACE-$SIDECAR_C_XAPP" -c "$SIDECAR_C_XAPP" --since=3m | tail -10
```

`[http-in] hello from xappd, served over the post-quantum tunnel` and
`[rmr-in] RMR:xappd:hello` - a BusyBox container doing plain `wget` and `nc` to
loopback.

**Per-sidecar counters:**

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for cid in "$SIDECAR_C_CLIENT_ID" "$SIDECAR_D_CLIENT_ID"; do pod=$(kubectl -n "$XAPP_NAMESPACE" get pod -l "pq.oran/sidecar=$cid" -o jsonpath='{.items[0].metadata.name}'); app=$(kubectl -n "$XAPP_NAMESPACE" get pod "$pod" -o jsonpath='{.spec.containers[1].name}'); echo "== $cid"; kubectl -n "$XAPP_NAMESPACE" exec "$pod" -c "$app" -- wget -q -O - "http://127.0.0.1:${SIDECAR_HEALTH_PORT}/stats"; echo; done
```

A handful of `egress_failed_*` with timestamps from before the second pod was ready is
the expected startup race - the sidecar retried and succeeded. Run the command twice a
minute apart: the `_ok_` counters must climb and the `_failed_` ones must stay frozen.
Confirm the reason if you want to be sure:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && kubectl -n "$XAPP_NAMESPACE" logs -l 'pq.oran/sidecar' -c pq-sidecar --prefix --tail=200 | grep egress_failed | cut -c1-300
```

`dial peer sidecar ... connection refused` or `no such host` is the race. **`peer
refused the token`** would be an authorization failure and needs investigating.

## 10B.11 Tearing it down

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && dms_cli uninstall --xapp_chart_name="$SIDECAR_C_XAPP" --namespace="$XAPP_NAMESPACE"; dms_cli uninstall --xapp_chart_name="$SIDECAR_D_XAPP" --namespace="$XAPP_NAMESPACE"; kubectl delete clusterpolicy pqc-xapp-auth-sidecar --ignore-not-found; kubectl -n "$XAPP_NAMESPACE" delete svc "$SIDECAR_C_CLIENT_ID-sidecar" "$SIDECAR_D_CLIENT_ID-sidecar" --ignore-not-found
```

---

**State after Chunk 10:** the whole framework is deployed and demonstrated. What is
left is measurement.

Next: `chunk-11-measurements.md`.
