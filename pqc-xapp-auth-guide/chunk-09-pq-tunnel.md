# Chunk 9 - The ML-KEM / ML-DSA secure channel

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


**Goal:** `sidecar/pqtunnel`, a `net.Conn` whose key establishment, peer
authentication and record protection are all post-quantum, on the Go standard library
alone.

**Needs the cluster?** No. Nothing here touches Kubernetes.

**Depends on:** `internal/pki` (Chunk 1) for `VerifyChain`, `KeyAlgName` and
`ThumbprintS256`. Nothing else in the project, and no third-party package.

---

## Why this is not TLS

Everything up to now rode on `crypto/tls` with `X25519MLKEM768` - a *hybrid* key
exchange, where an attacker must break both X25519 and ML-KEM. That is the right
default for production. But the research question is what a channel looks like when
the classical half is removed entirely, and `crypto/tls` will not let you do that: Go
exposes no ML-KEM-only group, and the certificate path still assumes a classical
handshake structure.

So the tunnel is its own protocol:

| Function | Algorithm | Standard | Package |
|---|---|---|---|
| Key establishment | ML-KEM-768 | FIPS 203 | `crypto/mlkem` |
| Peer authentication | ML-DSA-65 over the transcript | FIPS 204 | `crypto/mldsa` |
| Record protection | AES-256-GCM | - | `crypto/aes`, `crypto/cipher` |
| Key derivation | HKDF-SHA-256 | RFC 5869 | `crypto/hkdf` |

No cipher-suite negotiation, no resumption, no classical fallback. That is a
deliberate restriction, not a shortcut: with one fixed suite there is no downgrade
attack to analyse, and the whole handshake is two messages.

## Four design points worth defending

1. **The tunnel produces the identity the token is checked against.** `Conn.Peer()`
   carries `Thumbprint` - the RFC 8705 `x5t#S256` of the certificate that just proved
   possession of its ML-DSA key. In Chunk 10 the sidecar compares that against the
   token's `cnf.x5t#S256`. The binding is verified against a key the peer
   demonstrably holds, not a certificate it merely presented.
2. **Signatures are domain-separated.** `sign()` passes `contextClientHello` or
   `contextServerHello` as the ML-DSA context string, and the server's signature
   covers the client hello concatenated with its own. A client-hello signature cannot
   be replayed as a server hello, and the two messages are cryptographically welded.
3. **Nonces are sequence numbers, and they are checked.** Each direction has its own
   key, its own 4-byte IV and its own counter. `readRecord` compares the received
   nonce against the expected one in constant time *before* decrypting, so a
   reordered, duplicated or dropped record fails instead of being silently accepted.
4. **`CloseWrite` is an authenticated empty record.** TLS cannot express a half-close
   that reaches the peer application. Here it is a zero-length AES-GCM record that
   consumes a sequence number, so it cannot be forged or replayed, and the reader
   turns it into `io.EOF`. That is what lets an RMR one-shot message propagate
   end-of-stream through two sidecars.

## A property to be honest about: no alerts

When a peer rejects a certificate it simply returns - it never tells the other side
why, or that anything happened. TLS would send a fatal alert. The upside is a smaller
state machine and no downgrade surface; the cost is that a refused peer learns
nothing, which is why the sidecar in Chunk 10 logs the rejection reason locally rather
than returning it on the wire.

The practical consequence shows up in the tests: a rejecting server that does not
close its socket leaves the client blocked until its handshake deadline. The test
helper closes it, exactly as the real sidecar's `defer conn.Close()` does - without
that, `TestUntrustedPeerIsRejected` passes by timing out after 20 seconds instead of
failing fast.

## 9.1 The directory

```bash
mkdir -p ~/pqc-xapp-auth/sidecar/pqtunnel
```

## 9.2 Framing

Every wire message is a 4-byte big-endian length followed by its payload, and every
field inside a handshake message is length-prefixed too, so a parsed message is
unambiguous. `MaxFrame` is 1 MiB because ML-DSA certificate chains run to tens of
kilobytes.

```bash
cat > ~/pqc-xapp-auth/sidecar/pqtunnel/frame.go <<'PQTUNNEL_FRAME_GO_EOF'
package pqtunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame caps a single wire frame. Handshake messages carry ML-DSA certificate
// chains (a few tens of kilobytes); data records are capped at RecordSize.
const MaxFrame = 1 << 20

// ErrFrameTooLarge is returned when a peer announces a frame beyond MaxFrame.
var ErrFrameTooLarge = errors.New("pqtunnel: frame exceeds maximum size")

// writeFrame writes a 4-byte big-endian length followed by the payload.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrame {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads one length-prefixed frame.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return nil, fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// appendField appends a 4-byte length-prefixed field; the handshake messages are
// built from these so that every parsed message is unambiguous.
func appendField(dst, field []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(field)))
	return append(append(dst, hdr[:]...), field...)
}

// reader walks a handshake message field by field.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) field(name string) ([]byte, error) {
	if r.pos+4 > len(r.buf) {
		return nil, fmt.Errorf("truncated handshake: no length for %s", name)
	}
	n := int(binary.BigEndian.Uint32(r.buf[r.pos:]))
	r.pos += 4
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, fmt.Errorf("truncated handshake: %s declares %d bytes, %d remain", name, n, len(r.buf)-r.pos)
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) done() error {
	if r.pos != len(r.buf) {
		return fmt.Errorf("handshake message has %d trailing bytes", len(r.buf)-r.pos)
	}
	return nil
}
PQTUNNEL_FRAME_GO_EOF
```


## 9.3 Identity

`authenticate` is the gate: chain verification against the RIC CA, a hard requirement
that the leaf key is ML-DSA, and an optional expected-peer check.

```bash
cat > ~/pqc-xapp-auth/sidecar/pqtunnel/identity.go <<'PQTUNNEL_IDENTITY_GO_EOF'
package pqtunnel

import (
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/oran-ricsec/pqc-xapp-auth/internal/pki"
)

// Peer is the authenticated identity of the other end of a tunnel: the certificate
// chain it presented and proved possession of during the handshake.
type Peer struct {
	Chain []*x509.Certificate // leaf first, as presented
	Leaf  *x509.Certificate
	Alg   string // leaf public key algorithm, e.g. ML-DSA-65
	// Thumbprint is the RFC 8705 x5t#S256 of the leaf certificate, which is what a
	// certificate-bound access token carries in cnf.x5t#S256.
	Thumbprint string
}

// CommonName is the leaf subject CN, which the RIC CA sets to the xApp client id.
func (p *Peer) CommonName() string {
	if p == nil || p.Leaf == nil {
		return ""
	}
	return p.Leaf.Subject.CommonName
}

// encodeChain serialises a certificate chain as count || (len || DER)*.
func encodeChain(chain [][]byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(chain)))
	for _, der := range chain {
		out = appendField(out, der)
	}
	return out
}

func decodeChain(b []byte) ([]*x509.Certificate, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	n := int(binary.BigEndian.Uint32(b[:4]))
	if n == 0 || n > 8 {
		return nil, fmt.Errorf("certificate chain declares %d certificates", n)
	}
	r := &reader{buf: b, pos: 4}
	chain := make([]*x509.Certificate, 0, n)
	for i := 0; i < n; i++ {
		der, err := r.field(fmt.Sprintf("certificate %d", i))
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return chain, nil
}

// authenticate verifies a presented chain against the trust anchors and, when
// peerName is set, against the expected subject. It returns the authenticated peer.
// The caller has already verified that the leaf key signed the handshake transcript.
func authenticate(chain []*x509.Certificate, roots *x509.CertPool, peerName string, now time.Time, eku x509.ExtKeyUsage) (*Peer, error) {
	if kind, err := pki.VerifyChain(chain, roots, now, eku); err != nil {
		return nil, fmt.Errorf("peer certificate rejected (%s): %w", kind, err)
	}
	leaf := chain[0]
	if _, ok := leaf.PublicKey.(*mldsa.PublicKey); !ok {
		return nil, fmt.Errorf("peer certificate key is %s; the tunnel requires an ML-DSA key", pki.KeyAlgName(leaf.PublicKey))
	}
	if peerName != "" && !matchesName(leaf, peerName) {
		return nil, fmt.Errorf("peer certificate CN=%q SAN=%v is not the expected peer %q", leaf.Subject.CommonName, leaf.DNSNames, peerName)
	}
	return &Peer{Chain: chain, Leaf: leaf, Alg: pki.KeyAlgName(leaf.PublicKey), Thumbprint: pki.ThumbprintS256(leaf)}, nil
}

func matchesName(leaf *x509.Certificate, want string) bool {
	if strings.EqualFold(leaf.Subject.CommonName, want) {
		return true
	}
	for _, dns := range leaf.DNSNames {
		if strings.EqualFold(dns, want) {
			return true
		}
	}
	return false
}

// signerFor returns the ML-DSA private key and DER chain of a credential.
func signerFor(cert *tls.Certificate) (crypto.Signer, [][]byte, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, fmt.Errorf("no identity certificate available yet")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("identity private key does not implement crypto.Signer")
	}
	if _, ok := signer.Public().(*mldsa.PublicKey); !ok {
		return nil, nil, fmt.Errorf("identity key is %s; the tunnel requires an ML-DSA key", pki.KeyAlgName(signer.Public()))
	}
	return signer, cert.Certificate, nil
}

// sign produces an ML-DSA signature over the transcript with a domain-separating
// context string, so a client hello signature can never be replayed as a server one.
func sign(key crypto.Signer, context string, transcript []byte) ([]byte, error) {
	return key.Sign(nil, transcript, &mldsa.Options{Context: context})
}

func verify(pub crypto.PublicKey, context string, transcript, sig []byte) error {
	key, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return fmt.Errorf("peer key is not ML-DSA")
	}
	return mldsa.Verify(key, transcript, sig, &mldsa.Options{Context: context})
}
PQTUNNEL_IDENTITY_GO_EOF
```


## 9.4 The handshake

Two messages. The client sends its chain and an ML-KEM encapsulation key, signed. The
server authenticates it, encapsulates to that key, and signs **both** messages. The
SHA-256 of the two becomes the HKDF salt, so the record keys are bound to both
certificates, the encapsulation key and both signatures.

Note `Credential func() *tls.Certificate` - a callback, not a value. It is called on
every handshake, so a Method B rotation takes effect on the next connection with
nothing rebuilt.

```bash
cat > ~/pqc-xapp-auth/sidecar/pqtunnel/handshake.go <<'PQTUNNEL_HANDSHAKE_GO_EOF'
// Package pqtunnel implements the post-quantum secure channel that carries xApp
// traffic between sidecars.
//
// It is the handshake used by the ORAN-PQC tunnel work, re-implemented on the Go
// standard library so the sidecar stays a static binary with no cgo and no liboqs:
//
//	key establishment   ML-KEM-768        (FIPS 203, crypto/mlkem)
//	peer authentication ML-DSA-65         (FIPS 204, crypto/mldsa) over the transcript
//	record protection   AES-256-GCM       (crypto/aes, crypto/cipher)
//	key derivation      HKDF-SHA-256      (RFC 5869, crypto/hkdf)
//
// It is not TLS: there is no cipher-suite negotiation, no session resumption and no
// classical fallback. Both peers authenticate with an ML-DSA certificate issued by
// the RIC intermediate CA, and the resulting Peer is what the token binding is
// checked against: the certificate that proved possession here is the certificate
// the access token must be bound to.
package pqtunnel

import (
	"context"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// Wire constants.
const (
	magic   = "PQTB1"
	version = byte(1)
	// suiteMLKEM768MLDSAAESGCM identifies the fixed algorithm set; there is no negotiation.
	suiteMLKEM768MLDSAAESGCM = byte(1)

	contextClientHello = "PQTB1 client hello"
	contextServerHello = "PQTB1 server hello"
	infoClientToServer = "PQTB1 c2s"
	infoServerToClient = "PQTB1 s2c"
)

// Config is the tunnel configuration shared by both ends.
type Config struct {
	// Credential returns the current ML-DSA identity. It is called on every
	// handshake so a rotated certificate (method B) is picked up immediately.
	Credential func() *tls.Certificate
	// Roots are the trust anchors for the peer certificate (the RIC CA).
	Roots *x509.CertPool
	// PeerName, when set, is the CN or DNS SAN the peer certificate must carry.
	PeerName string
	// HandshakeTimeout bounds the whole handshake.
	HandshakeTimeout time.Duration
	// Now is the clock used for certificate validity; nil means time.Now.
	Now func() time.Time
}

func (c Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c Config) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 10 * time.Second
}

// Stats records what one handshake cost, for the measurement harness.
type Stats struct {
	Total     time.Duration
	KeyGen    time.Duration // ML-KEM key generation (client) or encapsulation (server)
	Sign      time.Duration
	Verify    time.Duration
	BytesSent int
	BytesRecv int
}

// Client performs the initiating half of the handshake over raw and returns the
// protected connection.
func Client(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	start := time.Now()
	var st Stats
	if err := setDeadline(ctx, raw, cfg.timeout()); err != nil {
		return nil, err
	}
	key, chain, err := signerFor(cfg.Credential())
	if err != nil {
		return nil, err
	}

	t0 := time.Now()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-768 key generation: %w", err)
	}
	st.KeyGen = time.Since(t0)

	body := []byte(magic)
	body = append(body, version, suiteMLKEM768MLDSAAESGCM)
	body = appendField(body, encodeChain(chain))
	body = appendField(body, dk.EncapsulationKey().Bytes())

	t0 = time.Now()
	sig, err := sign(key, contextClientHello, body)
	if err != nil {
		return nil, fmt.Errorf("client hello signature: %w", err)
	}
	st.Sign = time.Since(t0)

	clientHello := appendField(body, sig)
	if err := writeFrame(raw, clientHello); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}
	st.BytesSent = len(clientHello) + 4

	serverHello, err := readFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}
	st.BytesRecv = len(serverHello) + 4

	serverChain, ciphertext, serverSig, err := parseHello(serverHello, contextServerHello)
	if err != nil {
		return nil, err
	}
	// The server signature covers the client hello followed by everything in the
	// server hello up to the signature field, which binds the two messages together.
	signed := concat(clientHello, serverHello[:len(serverHello)-len(serverSig)-4])

	peer, err := authenticate(serverChain, cfg.Roots, cfg.PeerName, cfg.now(), x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	t0 = time.Now()
	if err := verify(peer.Leaf.PublicKey, contextServerHello, signed, serverSig); err != nil {
		return nil, fmt.Errorf("server hello signature: %w", err)
	}
	st.Verify = time.Since(t0)

	shared, err := dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ML-KEM-768 decapsulation: %w", err)
	}
	st.Total = time.Since(start)
	return newConn(raw, shared, transcript(clientHello, serverHello), peer, true, st)
}

// Server performs the responding half of the handshake.
func Server(ctx context.Context, raw net.Conn, cfg Config) (*Conn, error) {
	start := time.Now()
	var st Stats
	if err := setDeadline(ctx, raw, cfg.timeout()); err != nil {
		return nil, err
	}
	key, chain, err := signerFor(cfg.Credential())
	if err != nil {
		return nil, err
	}

	clientHello, err := readFrame(raw)
	if err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	st.BytesRecv = len(clientHello) + 4

	clientChain, ekBytes, clientSig, err := parseHello(clientHello, contextClientHello)
	if err != nil {
		return nil, err
	}
	peer, err := authenticate(clientChain, cfg.Roots, cfg.PeerName, cfg.now(), x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	t0 := time.Now()
	if err := verify(peer.Leaf.PublicKey, contextClientHello, clientHello[:len(clientHello)-len(clientSig)-4], clientSig); err != nil {
		return nil, fmt.Errorf("client hello signature: %w", err)
	}
	st.Verify = time.Since(t0)

	ek, err := mlkem.NewEncapsulationKey768(ekBytes)
	if err != nil {
		return nil, fmt.Errorf("client ML-KEM-768 encapsulation key: %w", err)
	}
	t0 = time.Now()
	shared, ciphertext := ek.Encapsulate()
	st.KeyGen = time.Since(t0)

	body := []byte(magic)
	body = append(body, version, suiteMLKEM768MLDSAAESGCM)
	body = appendField(body, encodeChain(chain))
	body = appendField(body, ciphertext)

	t0 = time.Now()
	sig, err := sign(key, contextServerHello, concat(clientHello, body))
	if err != nil {
		return nil, fmt.Errorf("server hello signature: %w", err)
	}
	st.Sign = time.Since(t0)

	serverHello := appendField(body, sig)
	if err := writeFrame(raw, serverHello); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}
	st.BytesSent = len(serverHello) + 4
	st.Total = time.Since(start)
	return newConn(raw, shared, transcript(clientHello, serverHello), peer, false, st)
}

// parseHello splits a hello message into chain, key material and signature. The
// signature covers everything that precedes it, which is what the caller re-derives.
func parseHello(msg []byte, what string) (chain []*x509.Certificate, keyMaterial, sig []byte, err error) {
	if len(msg) < len(magic)+2 || string(msg[:len(magic)]) != magic {
		return nil, nil, nil, fmt.Errorf("%s: bad magic", what)
	}
	if msg[len(magic)] != version {
		return nil, nil, nil, fmt.Errorf("%s: protocol version %d is not supported", what, msg[len(magic)])
	}
	if msg[len(magic)+1] != suiteMLKEM768MLDSAAESGCM {
		return nil, nil, nil, fmt.Errorf("%s: algorithm suite %d is not supported", what, msg[len(magic)+1])
	}
	r := &reader{buf: msg, pos: len(magic) + 2}
	rawChain, err := r.field("certificate chain")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	keyMaterial, err = r.field("key material")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	sig, err = r.field("signature")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := r.done(); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	chain, err = decodeChain(rawChain)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	return chain, keyMaterial, sig, nil
}

// transcript is the handshake hash; it salts the key derivation so the record keys
// are bound to both certificates, the encapsulation key and both signatures.
func transcript(clientHello, serverHello []byte) []byte {
	h := sha256.New()
	h.Write(clientHello)
	h.Write(serverHello)
	return h.Sum(nil)
}

// deriveKeys splits the ML-KEM shared secret into one AES-256-GCM key per direction.
func deriveKeys(shared, transcript []byte) (c2s, s2c []byte, err error) {
	if c2s, err = hkdf.Key(sha256.New, shared, transcript, infoClientToServer, 32); err != nil {
		return nil, nil, err
	}
	if s2c, err = hkdf.Key(sha256.New, shared, transcript, infoServerToClient, 32); err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	return append(append(out, a...), b...)
}

func setDeadline(ctx context.Context, c net.Conn, d time.Duration) error {
	deadline := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return c.SetDeadline(deadline)
}
PQTUNNEL_HANDSHAKE_GO_EOF
```


## 9.5 The protected connection

16 KiB records, a counter nonce per direction, a constant-time nonce check before
decryption, and the half-close marker. `WriteMessage`/`ReadMessage` carry the
sidecar's authorization frame inside the protected channel.

```bash
cat > ~/pqc-xapp-auth/sidecar/pqtunnel/conn.go <<'PQTUNNEL_CONN_GO_EOF'
package pqtunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// RecordSize is the largest plaintext carried by one AES-GCM record.
const RecordSize = 16 * 1024

// Conn is a net.Conn whose payload is protected with AES-256-GCM under keys derived
// from the ML-KEM shared secret. Each direction has its own key and its own record
// sequence number, and the nonce is a counter, so a reordered, duplicated or dropped
// record fails to decrypt instead of being silently accepted.
type Conn struct {
	net.Conn
	peer  *Peer
	stats Stats

	wmu     sync.Mutex
	seal    cipher.AEAD
	wIV     [4]byte
	wSeq    uint64
	wClosed bool

	rmu    sync.Mutex
	open   cipher.AEAD
	rIV    [4]byte
	rSeq   uint64
	rEOF   bool
	buffer []byte
}

func newConn(raw net.Conn, shared, transcript []byte, peer *Peer, isClient bool, st Stats) (*Conn, error) {
	c2s, s2c, err := deriveKeys(shared, transcript)
	if err != nil {
		return nil, fmt.Errorf("key derivation: %w", err)
	}
	c2sIV, err := hkdf.Key(sha256.New, shared, transcript, infoClientToServer+" iv", 4)
	if err != nil {
		return nil, err
	}
	s2cIV, err := hkdf.Key(sha256.New, shared, transcript, infoServerToClient+" iv", 4)
	if err != nil {
		return nil, err
	}
	sealKey, openKey, sealIV, openIV := c2s, s2c, c2sIV, s2cIV
	if !isClient {
		sealKey, openKey, sealIV, openIV = s2c, c2s, s2cIV, c2sIV
	}
	seal, err := newGCM(sealKey)
	if err != nil {
		return nil, err
	}
	open, err := newGCM(openKey)
	if err != nil {
		return nil, err
	}
	c := &Conn{Conn: raw, peer: peer, stats: st, seal: seal, open: open}
	copy(c.wIV[:], sealIV)
	copy(c.rIV[:], openIV)
	// Clear the handshake deadline; the proxy sets its own.
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Peer is the authenticated identity of the other end.
func (c *Conn) Peer() *Peer { return c.peer }

// HandshakeStats reports what the handshake cost.
func (c *Conn) HandshakeStats() Stats { return c.stats }

func nonce(iv [4]byte, seq uint64) []byte {
	var n [12]byte
	copy(n[:4], iv[:])
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// Write splits p into records and writes each as [length][nonce][ciphertext].
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wClosed {
		return 0, net.ErrClosed
	}
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > RecordSize {
			chunk = chunk[:RecordSize]
		}
		n := nonce(c.wIV, c.wSeq)
		record := make([]byte, 0, len(n)+len(chunk)+c.seal.Overhead())
		record = append(record, n...)
		record = c.seal.Seal(record, n, chunk, nil)
		if err := writeFrame(c.Conn, record); err != nil {
			return written, err
		}
		c.wSeq++
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Read returns plaintext from the next record, buffering any remainder.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.buffer) == 0 {
		if c.rEOF {
			return 0, io.EOF
		}
		plain, err := c.readRecord()
		if err != nil {
			return 0, err
		}
		// An empty record is the end-of-stream marker written by CloseWrite.
		if len(plain) == 0 {
			c.rEOF = true
			return 0, io.EOF
		}
		c.buffer = plain
	}
	n := copy(p, c.buffer)
	c.buffer = c.buffer[n:]
	return n, nil
}

func (c *Conn) readRecord() ([]byte, error) {
	record, err := readFrame(c.Conn)
	if err != nil {
		return nil, err
	}
	if len(record) < 12+c.open.Overhead() {
		return nil, io.ErrUnexpectedEOF
	}
	got, body := record[:12], record[12:]
	want := nonce(c.rIV, c.rSeq)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, fmt.Errorf("pqtunnel: record %d carries an out-of-sequence nonce", c.rSeq)
	}
	plain, err := c.open.Open(nil, want, body, nil)
	if err != nil {
		return nil, fmt.Errorf("pqtunnel: record %d failed authentication: %w", c.rSeq, err)
	}
	c.rSeq++
	return plain, nil
}

// CloseWrite ends this direction of the stream without tearing down the connection,
// so a half-close by the application reaches the peer application. TLS has no way to
// express this; here it is an authenticated empty record, which the reader turns into
// io.EOF. It cannot be forged or replayed, because it consumes a sequence number.
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wClosed {
		return nil
	}
	c.wClosed = true
	n := nonce(c.wIV, c.wSeq)
	c.wSeq++
	record := make([]byte, 0, len(n)+c.seal.Overhead())
	record = append(record, n...)
	record = c.seal.Seal(record, n, nil, nil)
	return writeFrame(c.Conn, record)
}

// MaxMessage caps a control message read with ReadMessage.
const MaxMessage = 64 * 1024

// WriteMessage writes one length-prefixed control message inside the protected
// channel. The sidecar uses it for the authorization frame and its acknowledgement.
func (c *Conn) WriteMessage(b []byte) error {
	if len(b) > MaxMessage {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	_, err := c.Write(append(hdr[:], b...))
	return err
}

// ReadMessage reads one control message written by WriteMessage.
func (c *Conn) ReadMessage() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessage {
		return nil, fmt.Errorf("%w: control message of %d bytes", ErrFrameTooLarge, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
PQTUNNEL_CONN_GO_EOF
```


## 9.6 The tests

Six cases over `net.Pipe()`, with a self-signed ML-DSA root standing in for the RIC
CA. The last one reaches inside the package to forge a record, which is why the test
lives in `package pqtunnel` and not `pqtunnel_test`.

```bash
cat > ~/pqc-xapp-auth/sidecar/pqtunnel/tunnel_test.go <<'PQTUNNEL_TUNNEL_TEST_GO_EOF'
package pqtunnel

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// testPKI builds a self-signed ML-DSA root and issues leaves from it, which is the
// shape of the RIC intermediate CA the sidecars really use.
type testPKI struct {
	roots *x509.CertPool
	key   crypto.Signer
	cert  *x509.Certificate
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test RIC CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testPKI{roots: pool, key: key, cert: cert}
}

func (p *testPKI) leaf(t *testing.T, cn string) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func (p *testPKI) config(cred *tls.Certificate, peerName string) Config {
	return Config{
		Credential:       func() *tls.Certificate { return cred },
		Roots:            p.roots,
		PeerName:         peerName,
		HandshakeTimeout: 20 * time.Second,
	}
}

// handshake runs both halves over a socket pair and returns the two ends.
func handshake(t *testing.T, clientCfg, serverCfg Config) (*Conn, *Conn, error) {
	t.Helper()
	c, s := net.Pipe()
	type result struct {
		conn *Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := Server(context.Background(), s, serverCfg)
		// A real sidecar closes the socket when it refuses a peer; without that the
		// client would block here until its handshake deadline expires.
		if err != nil {
			_ = s.Close()
		}
		ch <- result{conn, err}
	}()
	clientConn, clientErr := Client(context.Background(), c, clientCfg)
	res := <-ch
	if clientErr != nil {
		return nil, nil, clientErr
	}
	if res.err != nil {
		return nil, nil, res.err
	}
	return clientConn, res.conn, nil
}

func TestHandshakeAndRecords(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), "xapp-d"), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := server.Peer().CommonName(); got != "xapp-c" {
		t.Errorf("server sees peer %q, want xapp-c", got)
	}
	if got := client.Peer().CommonName(); got != "xapp-d" {
		t.Errorf("client sees peer %q, want xapp-d", got)
	}
	if got := client.Peer().Alg; got != "ML-DSA-65" {
		t.Errorf("peer algorithm %q, want ML-DSA-65", got)
	}
	if client.Peer().Thumbprint == "" || client.Peer().Thumbprint == server.Peer().Thumbprint {
		t.Error("each peer should expose the thumbprint of the other certificate")
	}

	// A payload larger than one record exercises the record splitting and the
	// sequence-numbered nonces in both directions.
	payload := strings.Repeat("o-ran", RecordSize/2)
	go func() {
		_, _ = io.WriteString(client, payload)
		_ = client.Close()
	}()
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload round trip: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestControlMessages(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), ""), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() { _ = client.WriteMessage([]byte(`{"v":1}`)) }()
	msg, err := server.ReadMessage()
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	if string(msg) != `{"v":1}` {
		t.Errorf("control message round trip: %q", msg)
	}
}

func TestUntrustedPeerIsRejected(t *testing.T) {
	good, rogue := newTestPKI(t), newTestPKI(t)
	// The client presents a certificate from a CA the server does not trust.
	_, _, err := handshake(t, rogue.config(rogue.leaf(t, "xapp-c"), ""), good.config(good.leaf(t, "xapp-d"), ""))
	if err == nil {
		t.Fatal("a peer from an untrusted CA was accepted")
	}
}

func TestWrongPeerNameIsRejected(t *testing.T) {
	pki := newTestPKI(t)
	_, _, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), "xapp-e"), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err == nil {
		t.Fatal("a peer with the wrong certificate subject was accepted")
	}
}

func TestTamperedRecordFailsAuthentication(t *testing.T) {
	pki := newTestPKI(t)
	// A raw pipe lets the test corrupt one byte of the ciphertext in flight.
	c, s := net.Pipe()
	type result struct {
		conn *Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := Server(context.Background(), s, pki.config(pki.leaf(t, "xapp-d"), ""))
		ch <- result{conn, err}
	}()
	client, err := Client(context.Background(), c, pki.config(pki.leaf(t, "xapp-c"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	res := <-ch
	if res.err != nil {
		t.Fatalf("handshake: %v", res.err)
	}
	// Forge a record with a valid nonce but a corrupted body.
	forged := append(nonce(client.wIV, 0), []byte("not a valid ciphertext")...)
	go func() { _ = writeFrame(c, forged) }()
	buf := make([]byte, 64)
	if _, err := res.conn.Read(buf); err == nil {
		t.Fatal("a forged record was accepted")
	}
}

func TestCloseWritePropagatesEOF(t *testing.T) {
	pki := newTestPKI(t)
	client, server, err := handshake(t, pki.config(pki.leaf(t, "xapp-c"), ""), pki.config(pki.leaf(t, "xapp-d"), ""))
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	go func() {
		_, _ = io.WriteString(client, "RMR:one-shot")
		_ = client.CloseWrite()
	}()
	got, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "RMR:one-shot" {
		t.Errorf("payload %q", got)
	}
	// The reverse direction must still work after a half-close.
	go func() {
		_, _ = io.WriteString(server, "ack")
		_ = server.CloseWrite()
	}()
	back, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(back) != "ack" {
		t.Errorf("reverse payload %q", back)
	}
}
PQTUNNEL_TUNNEL_TEST_GO_EOF
```


## 9.7 Check, build, test

```bash
cd ~/pqc-xapp-auth && for f in sidecar/pqtunnel/frame.go:81 sidecar/pqtunnel/identity.go:128 sidecar/pqtunnel/handshake.go:280 sidecar/pqtunnel/conn.go:220 sidecar/pqtunnel/tunnel_test.go:246; do p=${f%:*}; want=${f#*:}; got=$(wc -l < "$p" 2>/dev/null || echo MISSING); printf '%-42s got=%-8s want=%s\n' "$p" "$got" "$want"; done
```

Expected:

| File | Lines |
|---|---|
| `sidecar/pqtunnel/frame.go` | 81 |
| `sidecar/pqtunnel/identity.go` | 128 |
| `sidecar/pqtunnel/handshake.go` | 280 |
| `sidecar/pqtunnel/conn.go` | 220 |
| `sidecar/pqtunnel/tunnel_test.go` | 246 |


```bash
cd ~/pqc-xapp-auth && go build -p=2 ./... && go vet ./sidecar/...
```

```bash
cd ~/pqc-xapp-auth && go test -p=2 -v -count=1 ./sidecar/pqtunnel/
```

All six must pass:

```
--- PASS: TestHandshakeAndRecords
--- PASS: TestControlMessages
--- PASS: TestUntrustedPeerIsRejected
--- PASS: TestWrongPeerNameIsRejected
--- PASS: TestTamperedRecordFailsAuthentication
--- PASS: TestCloseWritePropagatesEOF
```

The whole package should finish in well under a second. If
`TestUntrustedPeerIsRejected` alone takes ~20 s, the `s.Close()` on the rejected
handshake in the test helper is missing - re-check that paste.

`go mod tidy` is **not** needed: every import is the standard library or
`internal/pki`. If `go build ./...` pulls anything new, something was pasted wrong.

## 9.8 Confirm it really is post-quantum end to end

```bash
cd ~/pqc-xapp-auth && grep -nE 'ecdsa|rsa\.|ed25519|curve25519|X25519|elliptic' sidecar/pqtunnel/*.go || echo "no classical public-key primitive in the tunnel"
```

```bash
cd ~/pqc-xapp-auth && grep -hoE 'crypto/(mlkem|mldsa|hkdf|aes|cipher|sha256|subtle)' sidecar/pqtunnel/*.go | sort -u
```

Seven packages, including `crypto/mlkem` and `crypto/mldsa`.

---

**State after Chunk 9:** the tunnel exists and is proven correct in isolation, but
nothing uses it. The deployment is unchanged.

Next: `chunk-10a-sidecar-code.md`.
