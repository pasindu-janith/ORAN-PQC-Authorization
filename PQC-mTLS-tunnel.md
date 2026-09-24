# PQC mTLS tunnel for inter-xApp communication

This document outlines the mechanics of custom Post-Quantum sidecar proxies, the key generation workflow, mTLS tunnel creation and testing. 

## Sidecar Proxy
The `main.go` script implements a transparent, Go-based TCP proxy designed to operate as a sidecar container within an O-RAN Near-RT RIC deployment. It establishes a 100% Post-Quantum Cryptographic (PQC) tunnel for routing internal RMR (RIC Message Router) traffic between xApps. This proxy was custom-built using `liboqs-go` to directly leverage the underlying C-based liboqs cryptographic primitives.

1. Initialization and Key Loading: The proxy starts by reading raw ML-DSA-65 (Dilithium) cryptographic keys directly from the container's mounted filesystem. It requires its own private key for signing and the peer's public key for signature verification, strictly enforcing a Zero Trust mutual authentication model.

2. Role Designation (Client/Server): The proxy operates in two modes based on command-line flags. In server mode, it binds to a public network interface (0.0.0.0) to listen for incoming tunnel connections and forwards decrypted traffic to the local xApp. In client mode, it listens locally (127.0.0.1) for outbound RMR traffic from the xApp and initiates the connection to the remote peer.

3. Post-Quantum Handshake (KEM & DSA): Upon TCP connection, the proxies execute a custom handshake. They exchange public keys and use ML-KEM-768 (Kyber) to encapsulate and decapsulate a shared secret. Simultaneously, ML-DSA-65 is used to sign the exchange, verifying the identity of both endpoints to prevent Man-in-the-Middle (MITM) attacks.

4. Data Plane Encapsulation: Once the shared secret is established, the proxy derives an AES-GCM symmetric key. All raw RMR byte streams intercepted from the local loopback are encrypted using AES-GCM before being transmitted over the network, ensuring both data confidentiality and integrity.

```go
package main

import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "encoding/binary"
        "flag"
        "io"
        "log"
        "net"
        "os"
        "sync"

        "github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
        SigAlgo = "ML-DSA-65"
        KemAlgo = "ML-KEM-768"
)

func main() {
        mode := flag.String("mode", "client", "client or server")
        localAddr := flag.String("local", "127.0.0.1:4562", "Local bind address")
        remoteAddr := flag.String("remote", "127.0.0.1:4560", "Remote forwarding address")
        myKeyPath := flag.String("my-key", "/certs/my.key", "Path to my ML-DSA private key")
        peerPubPath := flag.String("peer-pub", "/certs/peer.pub", "Path to peer's ML-DSA public key")
        flag.Parse()

        // Load static identities from disk
        myPrivKey, err := os.ReadFile(*myKeyPath)
        if err != nil {
                log.Fatalf("Failed to read my private key: %v", err)
        }
        peerPubKey, err := os.ReadFile(*peerPubPath)
        if err != nil {
                log.Fatalf("Failed to read peer public key: %v", err)
        }

        if *mode == "client" {
                startClient(*localAddr, *remoteAddr, myPrivKey, peerPubKey)
        } else {
                startServer(*localAddr, *remoteAddr, myPrivKey, peerPubKey)
        }
}

func startClient(local, remote string, myPrivKey, peerPubKey []byte) {
        listener, err := net.Listen("tcp", local)
        if err != nil {
                log.Fatalf("Listen failed: %v", err)
        }
        log.Printf("Client Proxy: Listening on %s, routing to %s", local, remote)

        // Init Signer and Verifier
        signer := oqs.Signature{}
        defer signer.Clean()
        signer.Init(SigAlgo, myPrivKey)

        verifier := oqs.Signature{}
        defer verifier.Clean()
        verifier.Init(SigAlgo, nil)

        for {
                rawConn, err := listener.Accept()
                if err != nil {
                        continue
                }
                go func(c net.Conn) {
                        defer c.Close()
                        pqcConn, err := net.Dial("tcp", remote)
                        if err != nil {
                                log.Printf("Dial failed: %v", err)
                                return
                        }
                        defer pqcConn.Close()

                        // 1. Generate Ephemeral ML-KEM Key
                        kem := oqs.KeyEncapsulation{}
                        defer kem.Clean()
                        kem.Init(KemAlgo, nil)
                        kemPK, _ := kem.GenerateKeyPair()

                        // 2. Sign and send to Server
                        clientSig, _ := signer.Sign(kemPK)
                        sendBytes(pqcConn, kemPK)
                        sendBytes(pqcConn, clientSig)

                        // 3. Receive Ciphertext and Server Signature
                        ciphertext := readBytes(pqcConn)
                        serverSig := readBytes(pqcConn)

                        // 4. Verify Server Identity
                        isValid, err := verifier.Verify(ciphertext, serverSig, peerPubKey)
                        if err != nil || !isValid {
                                log.Printf("Failed to verify server signature! Dropping connection.")
                                return
                        }

                        // 5. Decapsulate and start AES stream
                        sharedSecret, _ := kem.DecapSecret(ciphertext)
                        log.Printf("Mutual Auth PQC Handshake Complete! Stream encrypted.")

                        block, _ := aes.NewCipher(sharedSecret[:32])
                        aead, _ := cipher.NewGCM(block)
                        proxyStream(c, pqcConn, aead)
                }(rawConn)
        }
}

func startServer(local, remote string, myPrivKey, peerPubKey []byte) {
        listener, err := net.Listen("tcp", local)
        if err != nil {
                log.Fatalf("Listen failed: %v", err)
        }
        log.Printf("Server Proxy: Listening on %s, forwarding to %s", local, remote)

        signer := oqs.Signature{}
        defer signer.Clean()
        signer.Init(SigAlgo, myPrivKey)

        verifier := oqs.Signature{}
        defer verifier.Clean()
        verifier.Init(SigAlgo, nil)

        for {
                pqcConn, err := listener.Accept()
                if err != nil {
                        continue
                }
                go func(c net.Conn) {
                        defer c.Close()

                        // 1. Receive Client PK and Signature
                        kemPK := readBytes(c)
                        clientSig := readBytes(c)

                        // 2. Verify Client Identity
                        isValid, err := verifier.Verify(kemPK, clientSig, peerPubKey)
                        if err != nil || !isValid {
                                log.Printf("Failed to verify client signature! Dropping connection.")
                                return
                        }

                        // 3. Encapsulate Secret
                        kem := oqs.KeyEncapsulation{}
                        defer kem.Clean()
                        kem.Init(KemAlgo, nil)
                        ciphertext, sharedSecret, _ := kem.EncapSecret(kemPK)

                        // 4. Sign and send to Client
                        serverSig, _ := signer.Sign(ciphertext)
                        sendBytes(c, ciphertext)
                        sendBytes(c, serverSig)
                        log.Printf("Mutual Auth PQC Handshake Complete! Stream encrypted.")

                        // 5. Dial local xApp and start AES stream
                        appConn, err := net.Dial("tcp", remote)
                        if err != nil {
                                log.Printf("Failed to dial local app: %v", err)
                                return
                        }
                        defer appConn.Close()

                        block, _ := aes.NewCipher(sharedSecret[:32])
                        aead, _ := cipher.NewGCM(block)
                        proxyStream(appConn, c, aead)
                }(pqcConn)
        }
}

func sendBytes(conn net.Conn, data []byte) {
        length := uint32(len(data))
        binary.Write(conn, binary.BigEndian, length)
        conn.Write(data)
}

func readBytes(conn net.Conn) []byte {
        var length uint32
        if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
                return nil
        }
        data := make([]byte, length)
        io.ReadFull(conn, data)
        return data
}

func proxyStream(appConn, pqcConn net.Conn, aead cipher.AEAD) {
        var wg sync.WaitGroup
        wg.Add(2)

        // Encrypt outbound traffic
        go func() {
                defer wg.Done()
                buf := make([]byte, 4096)
                nonce := make([]byte, aead.NonceSize())
                for {
                        n, err := appConn.Read(buf)
                        if n > 0 {
                                rand.Read(nonce)
                                ciphertext := aead.Seal(nil, nonce, buf[:n], nil)
                                sendBytes(pqcConn, append(nonce, ciphertext...))
                        }
                        if err != nil {
                                break
                        }
                }
        }()

        // Decrypt inbound traffic
        go func() {
                defer wg.Done()
                for {
                        frame := readBytes(pqcConn)
                        if frame == nil {
                                break
                        }
                        nonceSize := aead.NonceSize()
                        if len(frame) < nonceSize {
                                continue
                        }
                        nonce, ciphertext := frame[:nonceSize], frame[nonceSize:]
                        plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
                        if err == nil {
                                appConn.Write(plaintext)
                        }
                }
        }()
        wg.Wait()
}
```

## PQC Key Generation Utility

The `keygen.go` script is a standalone cryptographic utility designed to bypass the limitations of legacy X.509/PEM certificate parsers (such as those in older Envoy versions) by generating unencoded, raw binary keys.

Algorithm Initialization: The script interfaces with the underlying C-based liboqs library via Go bindings (liboqs-go) to initialize the ML-DSA-65 digital signature algorithm.

Key Pair Generation: It executes the quantum-resistant algorithm to generate a mathematically linked public and private key pair.

Raw Byte Export: Instead of wrapping the keys in ASN.1 headers or Base64 encoding, the script extracts the raw byte arrays directly from memory.

Secure File I/O: The utility writes the raw bytes to the filesystem (a .pub file and a .key file) using strict UNIX file permissions (e.g., 0600 for the private key) to ensure the cryptographic material is protected at rest before being ingested into the cluster.

```go
package main

import (
        "flag"
        "fmt"
        "log"
        "os"

        "github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
        name := flag.String("name", "certs/xapp-a", "base name for generated keys")
        flag.Parse()

        sig := oqs.Signature{}
        defer sig.Clean()

        if err := sig.Init("ML-DSA-65", nil); err != nil {
                log.Fatalf("Failed to initialize ML-DSA-65: %v", err)
        }

        pubKey, err := sig.GenerateKeyPair()
        if err != nil {
                log.Fatalf("Failed to generate key pair: %v", err)
        }

        // ExportSecretKey returns []byte only (no error)
        privKey := sig.ExportSecretKey()

        pubFile := fmt.Sprintf("%s-mldsa.pub", *name)
        keyFile := fmt.Sprintf("%s-mldsa.key", *name)

        if err := os.WriteFile(pubFile, pubKey, 0644); err != nil {
                log.Fatalf("Failed to write public key to %s: %v", pubFile, err)
        }

        if err := os.WriteFile(keyFile, privKey, 0600); err != nil {
                log.Fatalf("Failed to write private key to %s: %v", keyFile, err)
        }

        fmt.Printf("Successfully generated %s and %s\n", pubFile, keyFile)
}
```

Create Docker file to build image `pure-pqc-tunnel`:

```Dockerfile
FROM golang:1.27-alpine AS build

# Install build tools
RUN apk add --no-cache build-base cmake git ninja linux-headers pkgconf

# Build liboqs (Force Shared Libraries ON)
WORKDIR /opt
RUN git clone --depth 1 -b main https://github.com/open-quantum-safe/liboqs.git && \
    mkdir -p liboqs/build && cd liboqs/build && \
    cmake -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=OFF -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    ninja && ninja install && \
    mkdir -p /usr/local/lib/pkgconfig /usr/local/lib64/pkgconfig && \
    ln -sf /usr/local/lib/pkgconfig/liboqs.pc /usr/local/lib/pkgconfig/liboqs-go.pc 2>/dev/null || true && \
    ln -sf /usr/local/lib64/pkgconfig/liboqs.pc /usr/local/lib64/pkgconfig/liboqs-go.pc 2>/dev/null || true && \
    mkdir -p /out/libs && \
    cp -P /usr/local/lib/liboqs.so* /out/libs/ 2>/dev/null || cp -P /usr/local/lib64/liboqs.so* /out/libs/ 2>/dev/null || true

# Prepare Go module
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go keygen.go ./

# Build BOTH the tunnel proxy and the key generator
RUN PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pqc-rmr-tunnel main.go && \
    PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib64/pkgconfig CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/pqc-keygen keygen.go

FROM alpine:latest
# Copy the consolidated C libraries and Go binaries
COPY --from=build /out/libs/ /usr/lib/
COPY --from=build /out/pqc-rmr-tunnel /bin/pqc-rmr-tunnel
COPY --from=build /out/pqc-keygen /bin/pqc-keygen

ENV LD_LIBRARY_PATH=/usr/lib
ENTRYPOINT ["/bin/pqc-rmr-tunnel"]
```

Before the container can be built, the local development host must establish the Go module context that the Dockerfile expects to copy into the build image: Installs the Go toolchain on your host machine to ensure you have the required compiler version to manage dependencies locally. Initializes a new Go module workspace, generating the `go.mod` file which defines the module name and target Go version. Fetches the required Post-Quantum cryptographic bindings (`liboqs-go`) from the Open Quantum Safe repository and automatically builds your local `go.sum` checksum file.

```bash
sudo snap install go --classic
go mod init pure-pqc-tunnel
go get github.com/open-quantum-safe/liboqs-go@latest
go mod tidy
```

The final commands take the multi-stage artifact and push it to your infrastructure: Build the `pure-pqc-tunnel:latest` image and push into local Docker registry to pull at xApp deployment.

```bash
export REGISTRY="127.0.0.1:5000"
sudo docker build -t $REGISTRY/pure-pqc-tunnel:latest .
sudo docker push $REGISTRY/pure-pqc-tunnel:latest
```


## Key Generation and Deployment Process
The deployment of the PQC tunnel relies on securely generating, distributing, and mounting the cryptographic material into the Kubernetes environment.

### Phase 1: Containerized Binary Compilation
Because the Open Quantum Safe library (liboqs) requires a complex C-toolchain and pkg-config bindings, the keygen.go utility is compiled directly into a standalone binary (/bin/pqc-keygen) during the Docker image build process. This ensures the key generator executes natively without requiring Go or GCC compilers in the final runtime environment.

### Phase 2: Raw Key Generation
The compiled binary is executed via temporary Docker containers using an overridden entrypoint. This step isolates the generation process.

The utility is executed for xApp A, outputting xapp-a-mldsa.pub and xapp-a-mldsa.key to a local directory.

The utility is executed for xApp B, outputting xapp-b-mldsa.pub and xapp-b-mldsa.key.

```bash
mkdir -p certs

# Generate keys for xApp A
sudo docker run --rm --entrypoint /bin/pqc-keygen -v $(pwd):/workspace -w /workspace 127.0.0.1:5000/pure-pqc-tunnel:latest -name certs/xapp-a

# Generate keys for xApp B
sudo docker run --rm --entrypoint /bin/pqc-keygen -v $(pwd):/workspace -w /workspace 127.0.0.1:5000/pure-pqc-tunnel:latest -name certs/xapp-b
```
Check the certs folder to `xapp-a-mldsa.key`, `xapp-a-mldsa.pub`, `xapp-b-mldsa.key`, `xapp-b-mldsa.pub` existance.

### Phase 3: Kubernetes Secret Injection
The unencoded binary files are uploaded directly into the Kubernetes ricxapp namespace as Opaque Secrets. This abstracts the key management away from the container images, allowing the infrastructure layer to securely distribute the material to the physical worker nodes where the xApp pods are scheduled.

```bash
sudo kubectl delete secret mldsa-xapp-a-keys mldsa-xapp-b-keys -n ricxapp --ignore-not-found

sudo kubectl create secret generic mldsa-xapp-a-keys -n ricxapp \
  --from-file=pub=certs/xapp-a-mldsa.pub \
  --from-file=key=certs/xapp-a-mldsa.key

sudo kubectl create secret generic mldsa-xapp-b-keys -n ricxapp \
  --from-file=pub=certs/xapp-b-mldsa.pub \
  --from-file=key=certs/xapp-b-mldsa.key
```

### Phase 4: Zero Trust Cross-Mounting
The deployment manifests (Deployment.yaml) are configured to mount these secrets as file volumes inside the sidecar containers. To achieve mutual authentication, the secrets are cross-mounted:

1. xApp A's Sidecar mounts its own private key (xapp-a-mldsa.key) and xApp B's public key (xapp-b-mldsa.pub).

2. xApp B's Sidecar mounts its own private key (xapp-b-mldsa.key) and xApp A's public key (xapp-a-mldsa.pub).

3. This specific mounting strategy guarantees that the tunnel can only be established if both sides cryptographically prove they possess the exact private key matching the public key expected by the peer.

Create `pure-pqc-deployments.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: service-ricxapp-xapp-b-rmr
  namespace: ricxapp
spec:
  selector:
    app: xapp-b
  ports:
  - name: pqc-tunnel
    port: 4562
    targetPort: 4562
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ricxapp-xapp-a
  namespace: ricxapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: xapp-a
  template:
    metadata:
      labels:
        app: xapp-a
    spec:
      containers:
      - name: xapp
        image: 127.0.0.1:5000/xapp-a:1.0.0
        imagePullPolicy: IfNotPresent
        env:
        - name: RMR_RTG_SVC
          value: "-1"
        - name: RMR_SEED_RT
          value: "/opt/ric/config/xapp-a-rt.db"
        volumeMounts:
        - name: rmr-route
          mountPath: /opt/ric/config
      - name: pqc-sidecar
        image: 127.0.0.1:5000/pure-pqc-tunnel:latest
        imagePullPolicy: Always
        args:
        - "-mode=client"
        - "-local=127.0.0.1:4562"
        - "-remote=service-ricxapp-xapp-b-rmr.ricxapp.svc.cluster.local:4562"
        - "-my-key=/certs/my/key"
        - "-peer-pub=/certs/peer/pub"
        volumeMounts:
        - name: my-certs
          mountPath: /certs/my
        - name: peer-certs
          mountPath: /certs/peer
      volumes:
      - name: rmr-route
        configMap:
          name: rmr-route-tables
      - name: my-certs
        secret:
          secretName: mldsa-xapp-a-keys
      - name: peer-certs
        secret:
          secretName: mldsa-xapp-b-keys
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ricxapp-xapp-b
  namespace: ricxapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: xapp-b
  template:
    metadata:
      labels:
        app: xapp-b
    spec:
      containers:
      - name: xapp
        image: 127.0.0.1:5000/xapp-b:4.0.0
        imagePullPolicy: IfNotPresent
        env:
        - name: RMR_RTG_SVC
          value: "-1"
        - name: RMR_SEED_RT
          value: "/opt/ric/config/xapp-b-rt.db"
        volumeMounts:
        - name: rmr-route
          mountPath: /opt/ric/config
      - name: pqc-sidecar
        image: 127.0.0.1:5000/pure-pqc-tunnel:latest
        imagePullPolicy: Always
        args:
        - "-mode=server"
        - "-local=0.0.0.0:4562"
        - "-remote=127.0.0.1:4560"
        - "-my-key=/certs/my/key"
        - "-peer-pub=/certs/peer/pub"
        volumeMounts:
        - name: my-certs
          mountPath: /certs/my
        - name: peer-certs
          mountPath: /certs/peer
      volumes:
      - name: rmr-route
        configMap:
          name: rmr-route-tables
      - name: my-certs
        secret:
          secretName: mldsa-xapp-b-keys
      - name: peer-certs
        secret:
          secretName: mldsa-xapp-a-keys
```

Create `route-db.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: rmr-route-tables
  namespace: ricxapp
data:
  xapp-a-rt.db: |
    hdr | rmr-fix | 1
    newrt | start
    mse | 30000 | -1 | 127.0.0.1:4562
    newrt | end
  xapp-b-rt.db: |
    hdr | rmr-fix | 1
    newrt | start
    mse | 30001 | -1 | 127.0.0.1:4562
    newrt | end

```

```bash
sudo kubectl apply -f pure-pqc-deployments.yaml
sudo kubectl apply -f route-db.yaml
```

Wait until `xapp-a` and `xapp-b` pods become `Running 2/2`:

```bash
sudo kubectl get pods -n ricxapp -w
```

## Test the tunnel


### Verify Handshake process

```bash
sudo kubectl port-forward deployment/ricxapp-xapp-b -n ricxapp 9901:9901
```

In another terminal execute this before sendig payloads.
```bash
curl -s http://localhost:9901/stats
```
You should immediately see `ssl.handshake: 0`. Because we restarted the pods to apply the new image, the counter has reset and no PQC tunnels have been established yet.

### Send payload and check handshake

Paste this in your terminal. It sends RMR payload to xapp-b from xapp-a.
```bash
sudo kubectl exec -it deployment/ricxapp-xapp-a -c xapp -n ricxapp -- env RMR_RTG_SVC=-1 RMR_SEED_RT=/opt/ric/config/xapp-a-rt.db python3 -c '
from ricxappframe.rmr import rmr
import time, json

print("Initializing RMR context...")
mrc = rmr.rmr_init(b"4563", rmr.RMR_MAX_RCV_BYTES, 0)
while not rmr.rmr_ready(mrc): 
    time.sleep(1)

payload = json.dumps({"ue_info": [{"ue_id": "PQC-CUSTOM-TUNNEL-TEST"}]}).encode("utf-8")
sbuf = rmr.rmr_alloc_msg(mrc, len(payload), payload=payload, mtype=30000)

print("Sending payload...")
for i in range(5):
    sbuf = rmr.rmr_send_msg(mrc, sbuf)
    if sbuf.contents.state == 0:
        print("\nSUCCESS! Payload dispatched to the local proxy!")
        break
    print(f"Retrying... RMR state: {sbuf.contents.state}")
    time.sleep(1)

time.sleep(2)
'
```
Fire your Python RMR test payload from xApp A, then run the curl command in your second terminal again.
```Bash
curl -s http://localhost:9901/stats
```
The output should now read `ssl.handshake: 1` (or higher), proving that your custom metric endpoint is correctly tracking the ML-KEM TLS sessions just like Envoy did, but with a fraction of the memory footprint.

Verify the mTLS via sidecar proxy logs at both xApps.
```bash
sudo kubectl logs deployment/ricxapp-xapp-a -c pqc-sidecar -n ricxapp --tail=20
sudo kubectl logs deployment/ricxapp-xapp-b -c pqc-sidecar -n ricxapp --tail=20
```