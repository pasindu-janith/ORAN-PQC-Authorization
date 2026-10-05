# Hand-build guide: post-quantum sender-constrained authorization for O-RAN xApps

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


Built on an OSC Near-RT RIC, in the `ricsec` namespace alongside `ricplt` and
`ricxapp`. This is not a separate testbed - it runs on the same cluster.

## Chunks

| # | File | What you have at the end | Cluster? |
|---|---|---|---|
| 0 | `chunk-00-prerequisites.md` | Go 1.27, project layout, the one config file | no |
| 1 | `chunk-01-pki.md` | SMO root + onboarding CA + RIC CA, classical **and** ML-DSA | no |
| 2 | `chunk-02-shared-libraries.md` | JOSE, PKI, networking, config, logging; tests pass | no |
| 3A | `chunk-03a-ca-code.md` | the enrollment service and SMO tool, compiled | no |
| 3B | `chunk-03b-ca-deploy.md` | `ric-ca` running; **Milestone 1**: one-time bootstrap proven | yes |
| 4 | `chunk-04-keycloak.md` | **Milestone 2**: a token carrying `cnf.x5t#S256` | yes |
| 5A | `chunk-05a-client-foundations.md` | client config, identity, issuance | no |
| 5B | `chunk-05b-client-core.md` | the `Client` core and the credential planes | no |
| 5C | `chunk-05c-client-methods.md` | Methods A/B/C; the client library builds | no |
| 6A | `chunk-06a-validator.md` | the validator, HTTP **and** channel, unit-tested | no |
| 6B | `chunk-06b-demo-xapp.md` | two xApps enforcing bindings on each other | yes |
| 6C | `chunk-06c-security-suite.md` | **46 cases, 46 passed** | yes |
| 7A | `chunk-07a-shim-code.md` | the ML-DSA re-signing shim, compiled | no |
| 7B | `chunk-07b-shim-deploy.md` | `pq-shim` serving ML-DSA over X25519MLKEM768 | yes |
| 8 | `chunk-08-pq-client-plane.md` | the walkthrough CLI; **all three methods post-quantum** | yes |
| 9 | `chunk-09-pq-tunnel.md` | the ML-KEM/ML-DSA channel, six tests passing | no |
| 10A | `chunk-10a-sidecar-code.md` | the sidecar, compiled | no |
| 10B | `chunk-10b-sidecar-deploy.md` | Kyverno injection, `dms_cli` onboarding, RMR+HTTP authorized | yes |
| 11 | `chunk-11-measurements.md` | `results/bench-{pq,classical}.csv` | yes |

## Two working habits that pay for themselves

**Paste one `cat >` block at a time, then run the chunk's `wc -l` check before
building.** Every chunk ends with one. A truncated or merged paste shows up in one
second as a wrong line count; the same mistake found by `go build` costs ten minutes
of confusing errors.

**If a directory listing appears while you paste**, your terminal is treating the tab
characters in Go source as tab-completion. Nothing else will work until that is fixed:

```bash
bind 'set enable-bracketed-paste on' && echo 'set enable-bracketed-paste on' >> ~/.inputrc
```

On an older readline, `bind 'set disable-completion on'` for the duration. Verify with
`printf '\tx\n' > /tmp/t; cat -A /tmp/t`, which must print `^Ix$`.

## Corrections folded into these documents

These were all mistakes made the first time through this build. They are fixed in the
documents, not repeated.

| Where | Problem | Fix |
|---|---|---|
| every chunk | two adjacent `cat <<'EOF'` blocks pasted together let the shell pair the delimiters wrongly, silently swallowing the second file into the first (`channel.go` ended up 202 lines and `channel_test.go` never existed) | every file has its own terminator, e.g. `<<'CHANNEL_TEST_GO_EOF'`, and the guide says to paste one block at a time |
| every chunk | a terminal without bracketed paste reads the tabs in Go source as tab-completion, printing a directory listing after every indented line and corrupting the file | the habit note above, with the `bind` fix and a one-line verification |
| Chunk 0 | `mkdir` created `ca/cmd` but not `ca/cmd/pki-gen`; `cat >` cannot create parent directories | the skeleton command creates **every** directory the guide needs |
| Chunk 0 / 4 | `KEYCLOAK_HEAP=-Xms256m -Xmx512m` unquoted - bash assigned the first word and tried to execute the second | the value is quoted |
| Chunk 0 / 8 / 10A | the derived `RESOURCE_*` values came from a Makefile conditional in the reference project and were dropped; the ConfigMap shipped the literal `${RESOURCE_JWKS_URL}` and every request was refused with `unsupported protocol scheme` | they are computed in `config/env.sh`, `render.sh` tolerates indentation, and 6B.5 cross-checks every manifest for surviving `${...}` |
| Chunk 0 / 8 / 10A | expected line counts quoted for `config/env.sh` | that file is edited in place across chunks, so its length is not a check; the derived variables are checked by name instead |
| Chunk 1 | claimed OpenSSL "cannot read" ML-DSA certificates | corrected: it parses the ASN.1 and prints the subject; it cannot interpret the key, verify the signature, or create one |
| Chunks 1-5 | several stated line counts were wrong | every expected count is computed from the file that is embedded |
| Chunk 3B | `ric-ca` had no `strategy`, so a RollingUpdate briefly ran two pods with two independent one-time ledgers - a bootstrap credential could be spent twice | `strategy: {type: Recreate}`; `replicas: 1` alone does not prevent it |
| Chunk 3B | `ric-ca` readiness was `httpGet ... scheme: HTTPS`, which can never pass once the CA presents an ML-DSA certificate (pod sits `0/1 Running`, zero restarts) | `tcpSocket: {port: https}`; the kubelet is a classical TLS client |
| Chunk 4 | `import-realm.sh` deletes the realm before importing, so malformed JSON costs you the realm entirely | the guide validates the rendered JSON with `json.load` first, and says why |
| Chunk 4 | `keycloak/ric-realm.json` had four clients; the two sidecar clients were spliced in later, and the splice was off by one line (cut before the `{` opening the first client, then re-emitted it) | the realm ships complete with all six clients from Chunk 4 |
| Chunk 5 | no warning that `xappclient` does not compile until 5C | 5A and 5B say so explicitly |
| Chunk 6A | `xapp-resource/channel.go` and `channel_test.go` were omitted, so the sidecar in Chunk 10 did not compile - discovered four chunks later | both ship in 6A, with the `ChannelOperation = "TUNNEL"` rationale |
| Chunk 6B | bootstrap Secrets created with `create secret tls`, whose `type` is immutable; a later `generic` update failed with `type: Invalid value: "Opaque": field is immutable`, the pods restarted onto already-spent credentials and crash-looped on `bootstrap_credential_reused` | `generic` consistently, and every update deletes before recreating |
| Chunk 6C | `build/host-env.sh` contains its own `EOF` line | the generated terminator avoids it, and `out/host.env` is deleted before every regeneration |
| Chunk 6C | `sectest`'s refusal message named Makefile targets that do not exist in this build | it names `PQ_MODE=false` and `scripts/run-method-{a,b,c}.sh --pq` |
| Chunk 6C | a CSV summary built with `awk -F,` gives wrong counts - several fields are quoted and contain commas | a `csv.DictReader` one-liner, with a note |
| Chunk 7B | the verification used `curl`, which cannot complete a handshake against an ML-DSA certificate over an ML-KEM-only key exchange on OpenSSL 1.1.1 - the check could never have passed | `cmd/pqprobe`, a small Go probe, and an explanation of why `curl` is the wrong tool here |
| Chunk 7B | `out/host.env` predated the `pq-shim` Service, so the probe failed on DNS | the chunk regenerates `out/host.env` before probing |
| Chunk 8 | `scripts/_run-method.sh` called `make build` and `make host-env` | it builds directly and calls `build/host-env.sh` |
| Chunk 8 | the CA restart clears the one-time ledger, which was not stated, and the bootstrap credentials were not re-minted before the pods restarted | both are called out, and the re-mint comes before the restart |
| Chunk 9 | `TestUntrustedPeerIsRejected` passed by timing out after 20 s, because the test's rejecting server never closed its socket | the helper closes it, as the real sidecar's `defer conn.Close()` does, and the guide explains what that reveals about the protocol having no alerts |
| Chunk 10B | a resource ConfigMap was named after the old project | everything is `pqc-xapp-auth` |
| Chunk 11 | the reference harness was classical-only and would have failed outright against a post-quantum deployment | `BENCH_PQ` defaults to `PQ_MODE`; new rows for `rotation_wall_latency`, `rotation_cert_size` and `access_token_size_ratio`; DPoP sizes measured with the ML-DSA signer |

## What the build produces

- **Three binding methods** on one implementation: RFC 8705 certificate-bound with a
  long-term key (A) and an ephemeral key (B) - the same code, parameterised - and
  RFC 9449 DPoP (C).
- **A post-quantum plane** selected by one flag: ML-DSA-65 identities and tokens,
  ML-DSA-44 DPoP proofs, X25519MLKEM768 required on every TLS leg.
- **An enforcement point** proven by 46 negative cases, each asserting a specific
  reason code.
- **A tunnel with no classical fallback**: ML-KEM-768, ML-DSA-65, AES-256-GCM,
  HKDF-SHA-256, on the Go standard library alone.
- **Platform-added security**: a stock BusyBox xApp, onboarded with `dms_cli`,
  gets sender-constrained post-quantum authorization on its HTTP *and* RMR traffic
  without a line of security code in the application.
- **Measurements** for both planes in one CSV schema.

## The exit condition, stated plainly

The shim exists because no released authorization server can sign an access token with
ML-DSA. RFC 9964 defines how (`kty: "AKP"`, `alg: ML-DSA-65`), and the Java platform
only got ML-DSA in JDK 24 and hybrid TLS key exchange in JDK 27. `PQ_ISSUER=keycloak`
points every consumer straight at the authorization server with no code change. That
is one variable, and it is the measure of how much of this design is a workaround and
how much is the architecture.
