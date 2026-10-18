# Keycloak Upgrade to Support ML-DSA-65

Create folder structure:

Create `pom.xml`
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>org.oran.zt</groupId>
    <artifactId>keycloak-mldsa-spi</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <keycloak.version>22.0.0</keycloak.version>
    </properties>

    <dependencies>
        <!-- 1. MUST BE AT THE VERY TOP for compile classpath priority -->
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.86</version>
        </dependency>

        <!-- 2. Keycloak dependencies with explicit exclusions of old BC -->
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-core</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
            <exclusions>
                <exclusion>
                    <groupId>org.bouncycastle</groupId>
                    <artifactId>bcprov-jdk18on</artifactId>
                </exclusion>
                <exclusion>
                    <groupId>org.bouncycastle</groupId>
                    <artifactId>bcpkix-jdk18on</artifactId>
                </exclusion>
            </exclusions>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi-private</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.5.1</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals><goal>shade</goal></goals>
                        <configuration>
                            <artifactSet>
                                <includes>
                                    <include>org.bouncycastle:bcprov-jdk18on</include>
                                </includes>
                            </artifactSet>
                            <relocations>
                                <relocation>
                                    <pattern>org.bouncycastle</pattern>
                                    <shadedPattern>org.oran.zt.bc</shadedPattern>
                                </relocation>
                            </relocations>
                            <filters>
                                <filter>
                                    <artifact>*:*</artifact>
                                    <excludes>
                                        <exclude>META-INF/*.SF</exclude>
                                        <exclude>META-INF/*.DSA</exclude>
                                        <exclude>META-INF/*.RSA</exclude>
                                        <exclude>META-INF/versions/**</exclude>
                                    </excludes>
                                </filter>
                            </filters>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

```java
package org.oran.zt.pqc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.signers.MLDSASigner;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;

public class MLDSASignatureProvider implements SignatureProvider {
    private final AsymmetricCipherKeyPair keyPair;
    private final String algorithm = "MLDSA65";

    public MLDSASignatureProvider(AsymmetricCipherKeyPair keyPair) { this.keyPair = keyPair; }

    @Override
    public SignatureSignerContext signer() { return createSigner(); }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) { return createSigner(); }

    private SignatureSignerContext createSigner() {
        return new SignatureSignerContext() {
            @Override
            public String getKid() { return "mldsa-key-1"; }

            @Override
            public String getAlgorithm() { return algorithm; }

            @Override
            public String getHashAlgorithm() { return "SHA-512"; }

            @Override
            public byte[] sign(byte[] data) throws SignatureException {
                try {
                    // Native Bouncy Castle 1.86 Lightweight API calls
                    MLDSASigner signer = new MLDSASigner();
                    signer.init(true, keyPair.getPrivate());
                    signer.update(data, 0, data.length);
                    return signer.generateSignature();
                } catch (Exception e) {
                    throw new SignatureException("ML-DSA-65 signing failed", e);
                }
            }
        };
    }
    @Override
    public SignatureVerifierContext verifier(String kid) { return null; }
    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) { return null; }
    @Override
    public boolean isAsymmetricAlgorithm() { return true; }
    @Override
    public void close() {}
}
```


```java
package org.oran.zt.pqc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;

import org.keycloak.Config;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Base64;

public class MLDSASignatureProviderFactory implements SignatureProviderFactory {
    public static final String ID = "MLDSA65";
    private AsymmetricCipherKeyPair keyPair;

    @Override
    public String getId() { return ID; }

    @Override
    public void init(Config.Scope config) {
        try {
            // BC 1.86 Lightweight API calls
            MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();
            MLDSAKeyGenerationParameters params = new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_65);
            kpg.init(params);
            this.keyPair = kpg.generateKeyPair();

            // Convert to standard X.509 format for Python verification
            byte[] x509Bytes = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(keyPair.getPublic()).getEncoded();
            String pem = "-----BEGIN PUBLIC KEY-----\n" +
                         Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(x509Bytes) +
                         "\n-----END PUBLIC KEY-----\n";

            try (FileOutputStream fos = new FileOutputStream("/tmp/mldsa_public.pem")) {
                fos.write(pem.getBytes());
            }
            System.out.println("[O-RAN ZT] ML-DSA-65 Keypair generated successfully using BC Lightweight API!");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize ML-DSA-65", e);
        }
    }

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new MLDSASignatureProvider(keyPair);
    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {}
    @Override
    public void close() {}
}
```


Create Dockerfile:
```Dockerfile
FROM quay.io/keycloak/keycloak:22.0.0 as builder

# The Fat JAR now contains everything needed
COPY target/keycloak-mldsa-spi-1.0.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:22.0.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

Build image:
```bash
mvn clean package
sudo docker build -t custom-keycloak-mldsa:1.8 .
sudo docker tag custom-keycloak-mldsa:1.8 127.0.0.1:5000/custom-keycloak-mldsa:1.8
sudo docker push 127.0.0.1:5000/custom-keycloak-mldsa:1.8
```

## Deployment of Keycloak

`updated-keycloak.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: keycloak-pqc
  namespace: keycloak
spec:
  selector:
    app: keycloak
  ports:
    - name: pqc-tunnel
      port: 4562
      targetPort: 4562
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  namespace: keycloak
spec:
  replicas: 1
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
        # --- INNER SERVER: Keycloak IAM ---
        - name: keycloak
          image: pasindujanith/custom-keycloak-mldsa:2.0  # Updated to custom image
          imagePullPolicy: Always            # Added to prevent pulling from external registries
          args: ["start-dev"]
          env:
            - name: KEYCLOAK_ADMIN
              value: "admin"
            - name: KEYCLOAK_ADMIN_PASSWORD
              value: "admin"
            # Enable HTTPS and Request Client Certificates for RFC 8705
            - name: KC_HTTPS_PORT
              value: "8443"
            - name: KC_HTTPS_CERTIFICATE_FILE
              value: "/certs/tls/tls.crt"
            - name: KC_HTTPS_CERTIFICATE_KEY_FILE
              value: "/certs/tls/tls.key"
            - name: KC_HTTPS_CLIENT_AUTH
              value: "request"
            - name: KC_TRUSTSTORE_PATHS
              value: "/certs/ca/ca.crt"
          volumeMounts:
            - name: keycloak-tls
              mountPath: /certs/tls
            - name: keycloak-truststore
              mountPath: /certs/ca

        # --- OUTER SHIM: PQC Tunnel Proxy ---
        - name: pqc-shim
          image: 127.0.0.1:5000/pure-pqc-tunnel:latest
          imagePullPolicy: Always
          args:
            - "-mode=server"
            - "-local=0.0.0.0:4562" # Listen for external PQC connections
            - "-remote=127.0.0.1:8443" # Forward decrypted stream to Keycloak HTTPS
            - "-my-key=/certs/pqc-my/key"
            - "-peer-pub=/certs/pqc-peer/pub"
          ports:
            - containerPort: 4562
          volumeMounts:
            - name: pqc-my-keys
              mountPath: /certs/pqc-my
            # Note: In a production mesh, this would mount a directory of allowed xApp public keys.
            # For this testbed, we mount xApp A's public key directly.
            - name: pqc-peer-keys
              mountPath: /certs/pqc-peer

      volumes:
        - name: keycloak-tls
          secret:
            secretName: keycloak-ecdsa-tls
        - name: keycloak-truststore
          secret:
            secretName: keycloak-truststore
        - name: pqc-my-keys
          secret:
            secretName: mldsa-keycloak-keys
        - name: pqc-peer-keys
          secret:
            secretName: mldsa-xapp-a-keys # Cross-mounted to verify xApp A
```

Apply to the cluster:
```yaml
sudo kubectl apply -f updated-keycloak.yaml
```

Retreive public key:
```bash
sudo kubectl exec -it deployment/keycloak -c keycloak -n keycloak -- cat /tmp/mldsa_public.pem > mldsa_public.pem
```