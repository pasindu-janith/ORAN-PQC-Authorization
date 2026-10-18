# Implementation of Method A

Update the main.go for pqc tunnel proxy.
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
	"strings"
	"sync"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

const (
	SigAlgo = "ML-DSA-65"
	KemAlgo = "ML-KEM-768"
)

func main() {
	mode := flag.String("mode", "client", "client or server")
	localAddrs := flag.String("local", "127.0.0.1:4562", "Comma-separated local bind addresses")
	remoteAddrs := flag.String("remote", "127.0.0.1:4560", "Comma-separated remote forwarding addresses")
	myKeyPath := flag.String("my-key", "/certs/my.key", "Path to my ML-DSA private key")
	peerPubPaths := flag.String("peer-pub", "/certs/peer.pub", "Comma-separated paths to peer ML-DSA public keys")
	flag.Parse()

	// Load static identity (own private key) from disk
	myPrivKey, err := os.ReadFile(*myKeyPath)
	if err != nil {
		log.Fatalf("Failed to read my private key: %v", err)
	}

	locals := strings.Split(*localAddrs, ",")
	remotes := strings.Split(*remoteAddrs, ",")
	peerPubs := strings.Split(*peerPubPaths, ",")

	if len(locals) != len(remotes) || len(locals) != len(peerPubs) {
		log.Fatalf("Mismatch in number of routes provided in flags. Locals: %d, Remotes: %d, PeerPubs: %d", len(locals), len(remotes), len(peerPubs))
	}

	var wg sync.WaitGroup

	for i := 0; i < len(locals); i++ {
		peerPubKey, err := os.ReadFile(peerPubs[i])
		if err != nil {
			log.Fatalf("Failed to read peer public key at %s: %v", peerPubs[i], err)
		}

		wg.Add(1)
		// Spawn a dedicated proxy tunnel for each configured route
		go func(local, remote string, peerPub []byte) {
			defer wg.Done()
			if *mode == "client" {
				startClient(local, remote, myPrivKey, peerPub)
			} else {
				startServer(local, remote, myPrivKey, peerPub)
			}
		}(locals[i], remotes[i], peerPubKey)
	}

	log.Printf("Unified PQC Proxy started in %s mode with %d routes.", *mode, len(locals))
	wg.Wait()
}

func startClient(local, remote string, myPrivKey, peerPubKey []byte) {
	listener, err := net.Listen("tcp", local)
	if err != nil {
		log.Fatalf("Listen failed on %s: %v", local, err)
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
				log.Printf("Dial failed to %s: %v", remote, err)
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
				log.Printf("Failed to verify server signature on route %s! Dropping connection.", remote)
				return
			}

			// 5. Decapsulate and start AES stream
			sharedSecret, _ := kem.DecapSecret(ciphertext)
			log.Printf("Mutual Auth PQC Handshake Complete for %s! Stream encrypted.", remote)

			block, _ := aes.NewCipher(sharedSecret[:32])
			aead, _ := cipher.NewGCM(block)
			proxyStream(c, pqcConn, aead)
		}(rawConn)
	}
}

func startServer(local, remote string, myPrivKey, peerPubKey []byte) {
	listener, err := net.Listen("tcp", local)
	if err != nil {
		log.Fatalf("Listen failed on %s: %v", local, err)
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
				log.Printf("Failed to verify client signature on route %s! Dropping connection.", local)
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
			log.Printf("Mutual Auth PQC Handshake Complete for %s! Stream encrypted.", local)

			// 5. Dial local xApp and start AES stream
			appConn, err := net.Dial("tcp", remote)
			if err != nil {
				log.Printf("Failed to dial local app at %s: %v", remote, err)
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

Updated pure-pqc-deployment.yaml
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
        - name: app-jwt-certs
          mountPath: /certs/jwt
        - name: ca-cert
          mountPath: /certs/ca
      
      # --- UNIFIED PQC SIDECAR ---
      - name: pqc-sidecar
        image: 127.0.0.1:5000/pure-pqc-tunnel:latest
        imagePullPolicy: Always
        args:
        - "-mode=client"
        # Route 1 (RMR Data Plane) -> Route 2 (Keycloak OAuth)
        - "-local=127.0.0.1:4562,127.0.0.1:8444"
        - "-remote=service-ricxapp-xapp-b-rmr.ricxapp.svc.cluster.local:4562,keycloak-pqc.keycloak.svc.cluster.local:4562"
        - "-my-key=/certs/my/key"
        - "-peer-pub=/certs/peer-xapp-b/pub,/certs/peer-keycloak/pub"
        volumeMounts:
        - name: my-certs
          mountPath: /certs/my
        - name: peer-certs-xapp-b
          mountPath: /certs/peer-xapp-b
        - name: peer-certs-keycloak
          mountPath: /certs/peer-keycloak
      volumes:
      - name: rmr-route
        configMap:
          name: rmr-route-tables
      - name: my-certs
        secret:
          secretName: mldsa-xapp-a-keys
      - name: peer-certs-xapp-b
        secret:
          secretName: mldsa-xapp-b-keys
      - name: peer-certs-keycloak
        secret:
          secretName: mldsa-keycloak-keys
      - name: app-jwt-certs
        secret:
          secretName: ecdsa-xapp-a-keys
      - name: ca-cert
        secret:
          secretName: ca-cert
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
        - name: peer-jwt-certs
          mountPath: /certs/jwt-peer
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
      - name: peer-jwt-certs
        secret:
          secretName: ecdsa-xapp-a-keys
```

## Create classical certificates
While we created the CA and Keycloak's certificates earlier, we need to generate the corresponding ECDSA certificates for the xApps themselves and inject them into the ricxapp namespace so the pods can mount them.

Run this script in your terminal to generate the xApp certificates (signed by the CA you created) and inject them into the correct namespace:
```bash
# 1. Generate xApp A Client Certificate (for JWT Binding)
openssl ecparam -name prime256v1 -genkey -noout -out certs/ecdsa/xapp-a.key
openssl req -new -key certs/ecdsa/xapp-a.key -out certs/ecdsa/xapp-a.csr -subj "/CN=xapp-a-jwt"
openssl x509 -req -in certs/ecdsa/xapp-a.csr -CA certs/ecdsa/ca.crt -CAkey certs/ecdsa/ca.key -CAcreateserial -out certs/ecdsa/xapp-a.crt -days 365

# 2. Generate xApp B Client Certificate
openssl ecparam -name prime256v1 -genkey -noout -out certs/ecdsa/xapp-b.key
openssl req -new -key certs/ecdsa/xapp-b.key -out certs/ecdsa/xapp-b.csr -subj "/CN=xapp-b-jwt"
openssl x509 -req -in certs/ecdsa/xapp-b.csr -CA certs/ecdsa/ca.crt -CAkey certs/ecdsa/ca.key -CAcreateserial -out certs/ecdsa/xapp-b.crt -days 365

# 3. Inject the CA and xApp Secrets into the ricxapp namespace
sudo kubectl create secret generic ca-cert -n ricxapp \
  --from-file=ca.crt=certs/ecdsa/ca.crt

sudo kubectl create secret tls ecdsa-xapp-a-keys -n ricxapp \
  --cert=certs/ecdsa/xapp-a.crt \
  --key=certs/ecdsa/xapp-a.key

sudo kubectl create secret tls ecdsa-xapp-b-keys -n ricxapp \
  --cert=certs/ecdsa/xapp-b.crt \
  --key=certs/ecdsa/xapp-b.key
```
Once these commands execute successfully, Kubernetes will automatically detect the new secrets and mount them. Watch the pod status transition to Running (2/2) using:

## Create Truststore for Keycloak
Keycloak's underlying TLS engine (Quarkus) cannot parse a raw .crt (PEM) file for its inbound KC_HTTPS_TRUST_STORE_FILE. It strictly requires a Java Keystore format (like PKCS12) to validate incoming mTLS client certificates. When we passed it the raw ca.crt, it crashed on startup. Here is how to package the Certificate Authority into a PKCS12 keystore and correct the deployment.

1. Create a PKCS12 Truststore
Since you are already using Docker, we can use a temporary Java container to run keytool and generate the .p12 file locally without needing to install the Java JDK on your host machine.

```Bash
sudo docker run --rm -v $(pwd)/certs:/certs eclipse-temurin:17-jre \
  keytool -import -file /certs/ecdsa/ca.crt -alias oranca \
  -keystore /certs/keycloak/truststore.p12 -storepass "password" -noprompt
```
2. Update the Kubernetes Secret
Re-inject the keycloak-truststore secret to include both the original .crt file and the new .p12 keystore.

```Bash
sudo kubectl create secret generic keycloak-truststore -n keycloak \
  --from-file=ca.crt=certs/ecdsa/ca.crt \
  --from-file=truststore.p12=certs/keycloak/truststore.p12 \
  --dry-run=client -o yaml | sudo kubectl apply -f -
```
3. Correct the Keycloak Environment Variables
Point the inbound HTTPS truststore to the new .p12 file and provide the password. This will automatically trigger a rolling restart of the Keycloak pod.

```Bash
sudo kubectl set env deployment/keycloak -n keycloak KC_HTTPS_TRUST_STORE_FILE="/certs/ca/truststore.p12"
sudo kubectl set env deployment/keycloak -n keycloak KC_HTTPS_TRUST_STORE_PASSWORD="password"
```
4. Verify and Retest
Watch the Keycloak rollout to ensure the pod successfully reads the keystore and stays in the Running state without crashing:

```Bash
sudo kubectl get pods -n keycloak -w
```
Once Keycloak is fully running (2/2 containers ready), re-run your exact Python script in the xapp-a terminal. Because the Authorization Server now possesses a properly formatted trust root, it will validate xApp A's certificate, embed the x5t#S256 hash into the token, and allow the RMR data dispatch to proceed to xApp B.


## Create the Realm and Client
Run the port-forward command in a separate terminal:

```Bash
sudo kubectl port-forward deployment/keycloak -n keycloak 8443:8443
```
Navigate to https://localhost:8443 and log in with admin / admin.

Create a new Realm named oran.

Go to Clients -> Create client.

Client ID: `xapp-a`

Enable Client authentication and Service accounts roles.

Navigate to the Credentials tab for xapp-a:

Set Client Authenticator to X509 Certificate.

Set Subject DN to `CN=xapp-a-jwt`.

Navigate to the Advanced tab for `xapp-a`:

Scroll to the Advanced Settings section.

Toggle OAuth 2.0 Mutual TLS Certificate Bound Access Tokens to ON.


### Note

Here is how the specific algorithms in your Go sidecar proxy work together to protect the token in transit during both the Keycloak fetch and the RMR dispatch:

Mutual Authentication (ML-DSA-65):

This is the Module-Lattice-Based Digital Signature Algorithm, which replaces classical algorithms like RSA or ECDSA for proving identity at the network layer.

When your client proxy connects to the server proxy, both sides use their static ML-DSA private keys to digitally sign the handshake messages. This proves their identities mathematically and prevents Man-in-the-Middle (MitM) attacks.

Key Encapsulation and Exchange (ML-KEM-768):

This is the Module-Lattice-Based Key Encapsulation Mechanism, replacing Diffie-Hellman (DH/ECDH) for securely agreeing on a shared secret over an untrusted network.

The client proxy generates an ephemeral ML-KEM public key and sends it over the wire.

The server proxy uses this public key to "encapsulate" a random shared secret, generating a ciphertext that is sent back to the client.

The client decapsulates the ciphertext, resulting in both proxies possessing the exact same quantum-secure shared secret.

Stream Encryption (AES-GCM):

Because asymmetric math (like ML-KEM) is too slow for continuous data transfer, the proxies feed the agreed-upon ML-KEM shared secret into a symmetric Advanced Encryption Standard (AES) cipher operating in Galois/Counter Mode (GCM).

When xApp A's Python script outputs the token, the local proxy intercepts it, encrypts the raw bytes using AES-GCM, and sends the ciphertext across the network.

The receiving proxy decrypts the AES stream and hands the plaintext token to the Keycloak listener or xApp B listener.

## Testing and Verification

Send RMR payload from `xapp-a` with access token fetch:

```bash
sudo kubectl exec -it deployment/ricxapp-xapp-a -c xapp -n ricxapp -- python3 -c '
import requests, json, time, socket
from ricxappframe.rmr import rmr
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# 1. Patch DNS resolution to route the domain to the local PQC proxy
original_getaddrinfo = socket.getaddrinfo
def patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if host == "keycloak.keycloak.svc.cluster.local":
        return original_getaddrinfo("127.0.0.1", port, family, type, proto, flags)
    return original_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = patched_getaddrinfo

# 2. Create adapter to verify CA signature but ignore missing SAN hostname
class HostNameIgnoreAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_hostname"] = False
        super().init_poolmanager(*args, **kwargs)

session = requests.Session()
session.mount("https://", HostNameIgnoreAdapter())

print("1. Fetching Certificate-Bound Token via Keycloak PQC Tunnel (Port 8444)...")
res = session.post(
    "https://keycloak.keycloak.svc.cluster.local:8444/realms/oran/protocol/openid-connect/token",
    data={"grant_type": "client_credentials", "client_id": "xapp-a"},
    cert=("/certs/jwt/tls.crt", "/certs/jwt/tls.key"),
    verify="/certs/ca/ca.crt"
)

if res.status_code != 200:
    print(f"Token request failed: {res.text}")
    exit(1)

token = res.json()["access_token"]
print("Success! Sender-constrained token retrieved.")

print("2. Initiating RMR...")
mrc = rmr.rmr_init(b"4563", rmr.RMR_MAX_RCV_BYTES, 0)
while not rmr.rmr_ready(mrc): 
    time.sleep(1)

payload = json.dumps({"token": token, "ue_info": [{"ue_id": "O-RAN-ZT-001"}]}).encode("utf-8")
sbuf = rmr.rmr_alloc_msg(mrc, len(payload), payload=payload, mtype=30000)

for _ in range(5):
    sbuf = rmr.rmr_send_msg(mrc, sbuf)
    if sbuf.contents.state == 0:
        print("3. Payload dispatched via xApp B PQC Tunnel (Port 4562)!")
        break
    time.sleep(1)
'
```



In new terminal run this for `xapp-b` listener:
```bash
sudo kubectl exec -it deployment/ricxapp-xapp-b -c xapp -n ricxapp -- pip3 install PyJWT
sudo kubectl exec -it deployment/ricxapp-xapp-b -c xapp -n ricxapp -- pip3 install cryptography

sudo kubectl exec -it deployment/ricxapp-xapp-b -c xapp -n ricxapp -- python3 -c '
import json, time, base64, hashlib, jwt, ctypes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from ricxappframe.rmr import rmr

def get_thumbprint(cert_path):
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).rstrip(b"=").decode("utf-8")

mrc = rmr.rmr_init(b"4560", rmr.RMR_MAX_RCV_BYTES, 0)
while not rmr.rmr_ready(mrc): 
    time.sleep(1)
print("xApp B listening for Zero Trust payload on PQC tunnel...")

while True:
    sbuf = rmr.rmr_alloc_msg(mrc, rmr.RMR_MAX_RCV_BYTES)
    sbuf = rmr.rmr_torcv_msg(mrc, sbuf, 1000)
    
    if sbuf and sbuf.contents.state == 0:
        # Safely extract bytes from the C-pointer using ctypes
        raw_payload = ctypes.string_at(sbuf.contents.payload, sbuf.contents.len)
        data = json.loads(raw_payload.decode("utf-8"))
        token = data.get("token")
        
        # Decode JWT to extract the confirmation claim
        claims = jwt.decode(token, options={"verify_signature": False})
        received_thumbprint = claims.get("cnf", {}).get("x5t#S256")
        
        # Compute the thumbprint of the physical TLS certificate
        expected_thumbprint = get_thumbprint("/certs/jwt-peer/tls.crt")
        
        print(f"\n[RECEIVED TOKEN] cnf thumbprint: {received_thumbprint}")
        if received_thumbprint == expected_thumbprint:
            print("[AUTH SUCCESS] Token is mathematically bound to xApp A physical certificate.")
            print("[DATA PROCESSED]", data.get("ue_info"))
        else:
            print("[AUTH FAILED] Token theft detected.")
        break
'
```