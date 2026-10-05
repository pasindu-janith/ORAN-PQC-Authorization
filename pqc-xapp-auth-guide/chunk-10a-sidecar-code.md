# Chunk 10A - The sidecar, offline

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


**Goal:** the five `sidecar/*.go` files and `cmd/xapp-sidecar`, compiling and vetted.

**Needs the cluster?** No.

**Depends on:** Chunk 6A's `xapp-resource/channel.go` and Chunk 9's `pqtunnel`.

---

## The idea in one paragraph

The sidecar is one process with two halves. **Egress** is a plain TCP listener on
loopback that the xApp writes to; the sidecar gets a bound token, opens a `pqtunnel`
connection to the peer sidecar, sends an authorization frame, then relays raw bytes.
**Ingress** is a `pqtunnel` listener on the pod address; the sidecar completes the
handshake, validates the frame, and only then dials the local application port. The
relay is byte-transparent, so HTTP and RMR both work and the xApp knows nothing about
any of it.

## Three points worth defending

- **The validator is not reimplemented.** `AuthorizeChannel` builds a synthetic
  `http.Request` whose `TLS.PeerCertificates` is the chain from the *tunnel*
  handshake, and calls the same `Authorize` the 46 cases exercise. One set of checks,
  two transports.
- **`htm` is `TUNNEL`, not `GET`.** A proof minted for a tunnel can never be replayed
  against an HTTP resource, or the other way round.
- **Two independent identities must agree.** After the token is accepted,
  `ingress.go` also checks that `p.ClientID` equals the tunnel peer's certificate CN.
  A stolen token cannot be presented over a tunnel authenticated with a different
  certificate.

## 10A.1 The directories

```bash
mkdir -p ~/pqc-xapp-auth/sidecar/cmd/xapp-sidecar ~/pqc-xapp-auth/deploy/kyverno ~/pqc-xapp-auth/xapps
```

## 10A.2 Configuration

Everything comes from the environment, which Kyverno fills in from pod annotations.
Routes use a compact `name|addr|peer|peerName` format so they survive a trip through a
Kubernetes annotation.

```bash
cat > ~/pqc-xapp-auth/sidecar/config.go <<'SIDECAR_CONFIG_GO_EOF'
// Package sidecar is the xApp sidecar: one container, injected next to an unmodified
// xApp, that carries the xApp traffic over a post-quantum tunnel and enforces
// sender-constrained access tokens on it.
//
// One process runs both directions:
//
//	egress   a plain TCP listener on loopback that the xApp writes to. The sidecar
//	         obtains a bound access token, opens a pqtunnel connection to the peer
//	         sidecar, sends an authorization frame and then relays bytes.
//	ingress  a pqtunnel listener on the pod address. The sidecar completes the
//	         handshake, validates the authorization frame with the resource-side
//	         validator and only then connects to the local application port.
//
// The relay is byte-transparent, so HTTP and RMR both work and neither the xApp nor
// the RMR library knows any of this is happening. Authorization is per connection:
// the tunnel handshake proves possession of the ML-DSA credential, and the
// authorization frame proves the access token is bound to that same credential.
package sidecar

import (
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/config"
)

// EgressRoute forwards one local listener to one peer sidecar.
type EgressRoute struct {
	Name     string // route label, matched against the peer ingress routes
	Listen   string // local address the xApp connects to
	Peer     string // peer sidecar address, host:port
	PeerName string // CN or DNS SAN the peer certificate must carry
}

// IngressRoute delivers one route label to one local application address.
type IngressRoute struct {
	Name  string
	Local string
}

// Config configures the sidecar. ConfigFromEnv reads it from the environment, which
// is what the Kyverno injection policy fills in from the pod annotations.
type Config struct {
	Name          string // this sidecar identity, the xApp client id
	Authority     string // host:port peers reach this sidecar on, as it appears in the proof htu
	IngressListen string // address the peer sidecars connect to ("" disables ingress)
	IngressRoutes []IngressRoute
	EgressRoutes  []EgressRoute

	HandshakeTimeout time.Duration
	AuthTimeout      time.Duration
	IdleTimeout      time.Duration
	DialTimeout      time.Duration
	TokenTimeout     time.Duration

	HealthListen string // plain HTTP health and metrics port for kubelet probes
}

// ConfigFromEnv reads the sidecar configuration.
//
//	SIDECAR_NAME            xapp-c
//	SIDECAR_AUTHORITY       xapp-c-sidecar.ricxapp.svc.cluster.local:4570
//	SIDECAR_INGRESS_LISTEN  :4570
//	SIDECAR_INGRESS_ROUTES  http|127.0.0.1:8080,rmr|127.0.0.1:4560
//	SIDECAR_EGRESS_ROUTES   http|127.0.0.1:18080|xapp-d-sidecar.ricxapp.svc.cluster.local:4570|xapp-d
func ConfigFromEnv() (Config, error) {
	e := &config.Env{}
	c := Config{
		Name:             e.Req("SIDECAR_NAME"),
		Authority:        e.Str("SIDECAR_AUTHORITY", ""),
		IngressListen:    e.Str("SIDECAR_INGRESS_LISTEN", ""),
		HandshakeTimeout: e.Dur("SIDECAR_HANDSHAKE_TIMEOUT", 15*time.Second),
		AuthTimeout:      e.Dur("SIDECAR_AUTH_TIMEOUT", 15*time.Second),
		IdleTimeout:      e.Dur("SIDECAR_IDLE_TIMEOUT", 0),
		DialTimeout:      e.Dur("SIDECAR_DIAL_TIMEOUT", 10*time.Second),
		TokenTimeout:     e.Dur("SIDECAR_TOKEN_TIMEOUT", 30*time.Second),
		HealthListen:     e.Str("SIDECAR_HEALTH_LISTEN", ":8081"),
	}
	ingress, err := parseIngress(e.Str("SIDECAR_INGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_INGRESS_ROUTES: %v", err)
	}
	c.IngressRoutes = ingress
	egress, err := parseEgress(e.Str("SIDECAR_EGRESS_ROUTES", ""))
	if err != nil {
		e.Fail("SIDECAR_EGRESS_ROUTES: %v", err)
	}
	c.EgressRoutes = egress
	if c.IngressListen == "" && len(c.EgressRoutes) == 0 {
		e.Fail("the sidecar has neither an ingress listener nor an egress route; nothing to do")
	}
	if c.IngressListen != "" && len(c.IngressRoutes) == 0 {
		e.Fail("SIDECAR_INGRESS_LISTEN is set but SIDECAR_INGRESS_ROUTES is empty")
	}
	if c.IngressListen != "" && c.Authority == "" {
		e.Fail("SIDECAR_AUTHORITY is required with an ingress listener: it is the host:port peers address this sidecar by")
	}
	return c, e.Err()
}

// IngressAuthority is the canonical authority and path of one served route; it must
// equal what the peer used to mint the proof.
func (c Config) IngressAuthority(route string) string { return c.Authority + "/" + route }

// IngressTarget returns the local address for a route label.
func (c Config) IngressTarget(name string) (string, bool) {
	for _, r := range c.IngressRoutes {
		if r.Name == name {
			return r.Local, true
		}
	}
	return "", false
}

func parseIngress(s string) ([]IngressRoute, error) {
	var out []IngressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) != 2 || f[0] == "" || f[1] == "" {
			return nil, fmt.Errorf("route %q is not name|host:port", spec)
		}
		out = append(out, IngressRoute{Name: f[0], Local: f[1]})
	}
	return out, nil
}

func parseEgress(s string) ([]EgressRoute, error) {
	var out []EgressRoute
	for _, spec := range splitList(s) {
		f := strings.Split(spec, "|")
		if len(f) < 3 || len(f) > 4 {
			return nil, fmt.Errorf("route %q is not name|listen|peer[|peerName]", spec)
		}
		r := EgressRoute{Name: f[0], Listen: f[1], Peer: f[2]}
		if len(f) == 4 {
			r.PeerName = f[3]
		}
		if r.Name == "" || r.Listen == "" || r.Peer == "" {
			return nil, fmt.Errorf("route %q has an empty field", spec)
		}
		out = append(out, r)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
SIDECAR_CONFIG_GO_EOF
```


## 10A.3 The authorization frame

```bash
cat > ~/pqc-xapp-auth/sidecar/auth.go <<'SIDECAR_AUTH_GO_EOF'
package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

// authFrame is the first control message on every tunnel connection. It carries the
// access token and, for a jkt-bound token, the proof of possession of the key the
// token is bound to. Nothing else flows until the peer has accepted it.
type authFrame struct {
	Version  int    `json:"v"`
	ClientID string `json:"client_id"`
	Route    string `json:"route"`
	Target   string `json:"target"`
	Token    string `json:"token"`
	Proof    string `json:"proof,omitempty"`
}

// authAck is the reply. A rejection carries the validator reason code, so the sending
// side logs exactly why it was refused instead of seeing a closed connection.
type authAck struct {
	OK      bool   `json:"ok"`
	Binding string `json:"binding,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Code    string `json:"code,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

const authFrameVersion = 1

// target is the canonical URI of one egress route, used as the proof htu.
func (r EgressRoute) target() string {
	return "https://" + r.Peer + "/" + r.Name
}

// buildAuthFrame obtains a currently valid bound token and, when the token is bound
// to a key rather than to a certificate, a fresh proof of possession of that key.
func (s *Sidecar) buildAuthFrame(ctx context.Context, route EgressRoute) (*authFrame, *xappclient.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.TokenTimeout)
	defer cancel()
	tok, err := s.client.Token(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("access token: %w", err)
	}
	f := &authFrame{
		Version:  authFrameVersion,
		ClientID: s.client.ClientID(),
		Route:    route.Name,
		Target:   route.target(),
		Token:    tok.Value,
	}
	if tok.Binding == "jkt" {
		d, ok := s.client.(xappclient.DPoP)
		if !ok {
			return nil, nil, fmt.Errorf("token is bound to cnf.jkt but this client holds no proof key")
		}
		signer := d.Signer()
		if tok.PostQuantum {
			if d.PQSigner() == nil {
				return nil, nil, fmt.Errorf("post-quantum token but no ML-DSA proof key")
			}
			signer = d.PQSigner()
		}
		proof, err := xappclient.BuildDPoPProof(signer, xappresource.ChannelOperation, f.Target, tok.Value, "", time.Now())
		if err != nil {
			return nil, nil, fmt.Errorf("channel proof: %w", err)
		}
		f.Proof = proof
	}
	return f, tok, nil
}

func encodeJSON(v any) ([]byte, error) { return json.Marshal(v) }

func decodeJSON(b []byte, v any) error { return json.Unmarshal(b, v) }
SIDECAR_AUTH_GO_EOF
```


## 10A.4 The process

Note the enrollment retry loop: up to 30 attempts rather than crash-looping, because a
crash-loop burns the one-time bootstrap credential - exactly the failure mode Chunk 8
warns about.

```bash
cat > ~/pqc-xapp-auth/sidecar/sidecar.go <<'SIDECAR_SIDECAR_GO_EOF'
package sidecar

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/sidecar/pqtunnel"
	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

// Sidecar is the injected process: an egress half that authorizes outgoing
// connections and an ingress half that enforces authorization on incoming ones.
type Sidecar struct {
	cfg       Config
	log       *slog.Logger
	client    xappclient.Client
	validator *xappresource.Validator

	mu      sync.Mutex
	counter map[string]int
}

// New builds a sidecar from the three configurations: its own, the token client and
// the resource validator. The client and the validator are the same ones the
// in-process integration uses; the sidecar only changes where they are applied.
func New(cfg Config, clientCfg xappclient.Config, resCfg xappresource.Config, log *slog.Logger) (*Sidecar, error) {
	if !clientCfg.PQEnabled {
		return nil, errors.New("the sidecar tunnel requires PQ_MODE=true: it authenticates peers with ML-DSA certificates")
	}
	client, err := xappclient.New(clientCfg, log)
	if err != nil {
		return nil, fmt.Errorf("token client: %w", err)
	}
	s := &Sidecar{cfg: cfg, log: log.With("component", "sidecar", "sidecar", cfg.Name), client: client, counter: map[string]int{}}
	if cfg.IngressListen != "" {
		v, err := xappresource.NewValidator(resCfg, client.HTTPClient(), log)
		if err != nil {
			return nil, fmt.Errorf("resource validator: %w", err)
		}
		s.validator = v
	}
	return s, nil
}

// Client exposes the token client, for the CLI walkthrough.
func (s *Sidecar) Client() xappclient.Client { return s.client }

// Run starts every listener and blocks until ctx is done.
func (s *Sidecar) Run(ctx context.Context) error {
	// The CA and Keycloak may still be starting; enrollment is retried rather than
	// crash-looping, which would burn the one-time bootstrap credential.
	for attempt := 1; ; attempt++ {
		err := s.client.Start(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt >= 30 {
			return fmt.Errorf("obtain identity: %w", err)
		}
		s.log.Warn("enrollment_retry", "attempt", attempt, "error", err.Error())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	d := s.client.Describe()
	s.log.Info("sidecar_ready",
		"method", d.Method, "client_id", d.ClientID, "pq_cert", d.PQCert, "pq_alg", d.PQAlg,
		"ingress", s.cfg.IngressListen, "egress_routes", len(s.cfg.EgressRoutes))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.client.Maintain(ctx)

	var wg sync.WaitGroup
	errs := make(chan error, len(s.cfg.EgressRoutes)+2)
	run := func(name string, f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil && ctx.Err() == nil {
				errs <- fmt.Errorf("%s: %w", name, err)
				cancel()
			}
		}()
	}

	if s.cfg.IngressListen != "" {
		run("ingress", func() error { return s.serveIngress(ctx) })
	}
	for _, route := range s.cfg.EgressRoutes {
		r := route
		run("egress "+r.Name, func() error { return s.serveEgress(ctx, r) })
	}
	if s.cfg.HealthListen != "" {
		run("health", func() error { return s.serveHealth(ctx) })
	}

	<-ctx.Done()
	wg.Wait()
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// tunnelConfig is the handshake configuration; Credential is read on every handshake
// so a rotated certificate takes effect on the next connection.
func (s *Sidecar) tunnelConfig(peerName string) pqtunnel.Config {
	return pqtunnel.Config{
		Credential: func() *tls.Certificate {
			if id := s.client.PQIdentity(); id != nil {
				return id.Current()
			}
			return nil
		},
		Roots:            s.client.TrustPool(),
		PeerName:         peerName,
		HandshakeTimeout: s.cfg.HandshakeTimeout,
	}
}

// relay copies in both directions and returns when either side closes.
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// acceptLoop runs fn for every accepted connection until ctx is done.
func (s *Sidecar) acceptLoop(ctx context.Context, l net.Listener, fn func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go fn(conn)
	}
}

func (s *Sidecar) count(name string) {
	s.mu.Lock()
	s.counter[name]++
	s.mu.Unlock()
}

// Counters returns a snapshot of the connection counters.
func (s *Sidecar) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counter))
	for k, v := range s.counter {
		out[k] = v
	}
	return out
}

// serveHealth exposes liveness and the counters over plain HTTP. It is plain because
// the kubelet cannot speak the post-quantum tunnel, and it carries no traffic.
func (s *Sidecar) serveHealth(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if s.client.PQIdentity() == nil || s.client.PQIdentity().Current() == nil {
			http.Error(w, "no identity yet", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		d := s.client.Describe()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sidecar": s.cfg.Name, "method": d.Method, "client_id": d.ClientID,
			"pq_cert": d.PQCert, "pq_alg": d.PQAlg, "counters": s.Counters(),
		})
	})
	srv := &http.Server{Addr: s.cfg.HealthListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
SIDECAR_SIDECAR_GO_EOF
```


## 10A.5 Egress

```bash
cat > ~/pqc-xapp-auth/sidecar/egress.go <<'SIDECAR_EGRESS_GO_EOF'
package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/sidecar/pqtunnel"
)

// serveEgress listens on the loopback address the xApp was pointed at and carries
// every connection to the peer sidecar over an authorized tunnel.
func (s *Sidecar) serveEgress(ctx context.Context, route EgressRoute) error {
	l, err := net.Listen("tcp", route.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", route.Listen, err)
	}
	s.log.Info("egress_listening", "route", route.Name, "listen", route.Listen, "peer", route.Peer, "peer_name", route.PeerName)
	return s.acceptLoop(ctx, l, func(local net.Conn) {
		defer local.Close()
		if err := s.forward(ctx, route, local); err != nil {
			s.count("egress_failed_" + route.Name)
			s.log.Warn("egress_failed", "route", route.Name, "peer", route.Peer, "error", err.Error())
		}
	})
}

func (s *Sidecar) forward(ctx context.Context, route EgressRoute, local net.Conn) error {
	start := time.Now()
	frame, tok, err := s.buildAuthFrame(ctx, route)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", route.Peer)
	if err != nil {
		return fmt.Errorf("dial peer sidecar %s: %w", route.Peer, err)
	}
	defer raw.Close()

	tun, err := pqtunnel.Client(ctx, raw, s.tunnelConfig(route.PeerName))
	if err != nil {
		return fmt.Errorf("tunnel handshake with %s: %w", route.Peer, err)
	}
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := encodeJSON(frame)
	if err != nil {
		return err
	}
	if err := tun.WriteMessage(payload); err != nil {
		return fmt.Errorf("send authorization frame: %w", err)
	}
	raw2, err := tun.ReadMessage()
	if err != nil {
		return fmt.Errorf("read authorization reply: %w", err)
	}
	var ack authAck
	if err := decodeJSON(raw2, &ack); err != nil {
		return fmt.Errorf("authorization reply is not JSON: %w", err)
	}
	if !ack.OK {
		s.count("egress_rejected_" + ack.Code)
		return fmt.Errorf("peer refused the token: %s (%s)", ack.Code, ack.Detail)
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}

	s.count("egress_ok_" + route.Name)
	s.log.Info("egress_authorized",
		"route", route.Name, "peer", route.Peer, "peer_cert", tun.Peer().CommonName(),
		"binding", tok.Binding, "cnf", tok.Thumbprint, "token_alg", tok.Alg, "post_quantum", tok.PostQuantum,
		"kex", "ML-KEM-768", "peer_sig_alg", tun.Peer().Alg,
		"handshake_ms", ms(hs.Total), "setup_ms", ms(time.Since(start)))

	relay(tun, local)
	return nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
SIDECAR_EGRESS_GO_EOF
```


## 10A.6 Ingress - the enforcement point

```bash
cat > ~/pqc-xapp-auth/sidecar/ingress.go <<'SIDECAR_INGRESS_GO_EOF'
package sidecar

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/sidecar/pqtunnel"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

// serveIngress accepts tunnel connections from peer sidecars. A connection reaches
// the application only after the handshake authenticated the peer certificate and the
// validator accepted the access token bound to it.
func (s *Sidecar) serveIngress(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.IngressListen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.cfg.IngressListen, err)
	}
	s.log.Info("ingress_listening", "listen", s.cfg.IngressListen, "routes", len(s.cfg.IngressRoutes))
	return s.acceptLoop(ctx, l, func(raw net.Conn) {
		defer raw.Close()
		if err := s.accept(ctx, raw); err != nil {
			s.log.Warn("ingress_failed", "remote", raw.RemoteAddr().String(), "error", err.Error())
		}
	})
}

func (s *Sidecar) accept(ctx context.Context, raw net.Conn) error {
	start := time.Now()
	tun, err := pqtunnel.Server(ctx, raw, s.tunnelConfig(""))
	if err != nil {
		s.count("ingress_handshake_failed")
		return fmt.Errorf("tunnel handshake: %w", err)
	}
	peer := tun.Peer()
	hs := tun.HandshakeStats()

	if err := tun.SetDeadline(time.Now().Add(s.cfg.AuthTimeout)); err != nil {
		return err
	}
	payload, err := tun.ReadMessage()
	if err != nil {
		s.count("ingress_no_auth_frame")
		return fmt.Errorf("read authorization frame: %w", err)
	}
	var frame authFrame
	if err := decodeJSON(payload, &frame); err != nil {
		return s.refuse(tun, "authorization_frame_malformed", err.Error())
	}
	if frame.Version != authFrameVersion {
		return s.refuse(tun, "authorization_frame_version", fmt.Sprintf("frame version %d is not supported", frame.Version))
	}
	local, ok := s.cfg.IngressTarget(frame.Route)
	if !ok {
		return s.refuse(tun, "route_unknown", fmt.Sprintf("route %q is not served here", frame.Route))
	}

	// The target the proof was minted for must be this sidecar and this route, not
	// some other destination the peer also talks to.
	want := "https://" + s.cfg.IngressAuthority(frame.Route)
	if frame.Target != want {
		return s.refuse(tun, "channel_target_mismatch", fmt.Sprintf("authorization frame targets %q, this route is %q", frame.Target, want))
	}

	p, rej := s.validator.AuthorizeChannel(ctx, xappresource.ChannelRequest{
		Token:     frame.Token,
		Proof:     frame.Proof,
		PeerChain: peer.Chain,
		Target:    frame.Target,
		Operation: xappresource.ChannelOperation,
	})
	if rej != nil {
		s.count("ingress_rejected_" + rej.Code)
		s.log.Warn("ingress_rejected",
			"route", frame.Route, "peer_cert", peer.CommonName(), "client_id", frame.ClientID,
			"reason_code", rej.Code, "reason", rej.Detail, "validation_ms", ms(time.Since(start)))
		return s.refuse(tun, rej.Code, rej.Detail)
	}

	// The token was accepted; the caller it names must also be the peer that
	// completed the handshake, so a stolen token cannot be presented over a tunnel
	// authenticated with a different certificate.
	if p.ClientID != "" && peer.CommonName() != "" && p.ClientID != peer.CommonName() {
		s.count("ingress_rejected_peer_identity_mismatch")
		return s.refuse(tun, "peer_identity_mismatch",
			fmt.Sprintf("token names client %q but the tunnel peer certificate is CN=%q", p.ClientID, peer.CommonName()))
	}

	if err := s.reply(tun, authAck{OK: true, Binding: p.Binding, Peer: s.cfg.Name}); err != nil {
		return err
	}
	if err := tun.SetDeadline(time.Time{}); err != nil {
		return err
	}
	s.count("ingress_ok_" + frame.Route)
	s.log.Info("ingress_authorized",
		"route", frame.Route, "client_id", p.ClientID, "peer_cert", peer.CommonName(), "peer_sig_alg", peer.Alg,
		"binding", p.Binding, "cnf", p.Thumbprint, "kex", "ML-KEM-768",
		"handshake_ms", ms(hs.Total), "authz_ms", ms(time.Since(start)), "target", local)

	app, err := (&net.Dialer{Timeout: s.cfg.DialTimeout}).DialContext(ctx, "tcp", local)
	if err != nil {
		s.count("ingress_app_unreachable")
		return fmt.Errorf("connect to the application at %s: %w", local, err)
	}
	defer app.Close()
	relay(app, tun)
	return nil
}

// refuse sends the reason to the peer and closes the connection.
func (s *Sidecar) refuse(tun *pqtunnel.Conn, code, detail string) error {
	if err := s.reply(tun, authAck{OK: false, Code: code, Detail: detail}); err != nil {
		return err
	}
	return fmt.Errorf("refused: %s (%s)", code, detail)
}

func (s *Sidecar) reply(tun *pqtunnel.Conn, ack authAck) error {
	b, err := encodeJSON(ack)
	if err != nil {
		return err
	}
	return tun.WriteMessage(b)
}
SIDECAR_INGRESS_GO_EOF
```


## 10A.7 The binary

```bash
cat > ~/pqc-xapp-auth/sidecar/cmd/xapp-sidecar/main.go <<'XAPP_SIDECAR_MAIN_GO_EOF'
// Command xapp-sidecar is the token-binding sidecar injected next to an xApp.
//
// It is configured entirely from the environment, which the Kyverno injection policy
// fills in from the pod annotations, so the xApp image and the xApp source stay
// untouched. See the sidecar package documentation for the traffic path.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/logx"
	"github.com/oran-ricsec/pqc-xapp-auth/sidecar"
	xappclient "github.com/oran-ricsec/pqc-xapp-auth/xapp-client"
	xappresource "github.com/oran-ricsec/pqc-xapp-auth/xapp-resource"
)

func main() {
	log := logx.New("xapp-sidecar")
	cfg, err := sidecar.ConfigFromEnv()
	if err != nil {
		log.Error("invalid sidecar configuration", "error", err)
		os.Exit(2)
	}
	clientCfg, err := xappclient.ConfigFromEnv()
	if err != nil {
		log.Error("invalid client configuration", "error", err)
		os.Exit(2)
	}
	resourceCfg, err := xappresource.ConfigFromEnv()
	if err != nil {
		log.Error("invalid resource configuration", "error", err)
		os.Exit(2)
	}

	s, err := sidecar.New(cfg, clientCfg, resourceCfg, log)
	if err != nil {
		log.Error("sidecar", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := s.Run(ctx); err != nil {
		log.Error("sidecar stopped", "error", err)
		os.Exit(1)
	}
	log.Info("sidecar stopped")
}
XAPP_SIDECAR_MAIN_GO_EOF
```


## 10A.8 Configuration for the sidecar deployment

This block belongs in `config/env.sh` **before** the derived block at the end of the
file, not appended after it. Write it to a temporary file first, then splice:

```bash
cat > /tmp/sidecar-env.txt <<'SIDECAR_ENV_EOF'
# --- Sidecar architecture (Chunk 10) ----------------------------------------
# One sidecar container per xApp carries both directions of its traffic over the
# post-quantum tunnel and enforces the token binding on it.
SIDECAR_IMAGE_NAME=xapp-sidecar
SIDECAR_PORT=4570
SIDECAR_HEALTH_PORT=8081
SIDECAR_IMAGE=ricsec/xapp-sidecar:0.1.0
SIDECAR_PULL_POLICY=Never
# The two onboarded xApps. C presents a certificate-bound token, D a DPoP-bound one,
# so one deployment exercises both binding checks on the tunnel.
SIDECAR_C_XAPP=xappc
SIDECAR_C_CLIENT_ID=xapp-sidecar-c
SIDECAR_C_METHOD=A
SIDECAR_D_XAPP=xappd
SIDECAR_D_CLIENT_ID=xapp-sidecar-d
SIDECAR_D_METHOD=C
# Ports inside the xApp pods: the app listens on APP_*, the sidecar listens on LOCAL_*
SIDECAR_APP_HTTP_PORT=8080
SIDECAR_APP_RMR_PORT=4560
SIDECAR_LOCAL_HTTP_PORT=18080
SIDECAR_LOCAL_RMR_PORT=14560
# Stock image the onboarded xApps run; it contains no security code at all
DEMO_APP_IMAGE_NAME=oran/busybox
DEMO_APP_IMAGE_TAG=1.36
# dms_cli needs a registry host for images and a chart repository to push to
LOCAL_REGISTRY=127.0.0.1:5000
CHART_REPO_URL=http://localhost:8090
KYVERNO_CHART_VERSION=3.3.9

SIDECAR_ENV_EOF
```

```bash
cd ~/pqc-xapp-auth && n=$(grep -n '^# --- Derived (computed' config/env.sh | cut -d: -f1) && echo "inserting before line $n" && { head -n $((n-1)) config/env.sh; cat /tmp/sidecar-env.txt; tail -n +$n config/env.sh; } > /tmp/env.new && mv /tmp/env.new config/env.sh
```

Verify by variable, not by line count:

```bash
cd ~/pqc-xapp-auth && set -a && source config/env.sh && set +a && for v in SIDECAR_PORT SIDECAR_C_CLIENT_ID SIDECAR_D_CLIENT_ID SIDECAR_IMAGE LOCAL_REGISTRY CHART_REPO_URL KYVERNO_CHART_VERSION DEMO_APP_IMAGE_NAME RESOURCE_JWKS_URL RIC_CA_SERVER_CERT; do printf '%-24s %s\n' "$v" "${!v:-<UNSET>}"; done
```

All ten set, with `RESOURCE_JWKS_URL` on the shim and
`RIC_CA_SERVER_CERT=ric-ca-server-pq` - that last pair proves the derived block is
still last and still correct.

## 10A.9 Check, build, test

```bash
cd ~/pqc-xapp-auth && for f in sidecar/config.go:155 sidecar/auth.go:81 sidecar/sidecar.go:218 sidecar/egress.go:86 sidecar/ingress.go:127 sidecar/cmd/xapp-sidecar/main.go:51; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `sidecar/config.go` | 155 |
| `sidecar/auth.go` | 81 |
| `sidecar/sidecar.go` | 218 |
| `sidecar/egress.go` | 86 |
| `sidecar/ingress.go` | 127 |
| `sidecar/cmd/xapp-sidecar/main.go` | 51 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && go vet ./sidecar/... ./xapp-resource/
```

```bash
cd ~/pqc-xapp-auth && go test -p=2 -count=1 ./...
```

Next: `chunk-10b-sidecar-deploy.md`.
