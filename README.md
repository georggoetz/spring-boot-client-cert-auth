## Generating server CA certificate

1. Generate rsa key encrypted with aes256. Length of key affects performance of SSL handshake. Longer more secure but slower.
    ```
    openssl genrsa -aes256 -out caprivate.key 2048
    ```
    Used **_changeit_** as pass phrase.

2. Create a x509 certificate with the previously generated key. 
    ```
    openssl req -x509 -new -nodes -key caprivate.key -sha256 -days 1024 -out ca.crt
    ```
    Fill out fields, CN must match domain name, in this case `localhost`.

3. Import the server CA certificate into the truststore. 
    ```
    keytool -import -file ca.crt -alias CA -keystore ca_truststore.jks
    ```
    Pass phrase is **_changeit_**.
4. Import server CA certificate into keystore
    ```
    openssl pkcs12 -export -in ca.crt -inkey caprivate.key -certfile ca.crt -out ca_keystore.p12 -name CA
    ```
    Passphrase is again **_changeit_**
5. Convert keystore to JKS format (optional)
    ```
    keytool -importkeystore -srckeystore keystore.p12 -srcstoretype pkcs12 -destkeystore keystore.jks -deststoretype JKS
    ```
    
## Enabling HTTPS

Configure application.yml to enable HTTPS
```yaml
server:
  port: 8443
  ssl:
    key-store: classpath:keystore.p12
    key-store-password: changeit
    trust-store: classpath:truststore.jks
    trust-store-password: changeit
    client-auth: need
```

## Generating client certificate for Alice

1. Alice generates a private key:
    ```
    openssl genrsa -aes256 -out aliceprivate.key 2048
    ```
    Passphrase is **_changeit_**
2. Then she creates a certificate signing request (CSR) and signs it with her private key.
    ```
    openssl req -new -key aliceprivate.key -out alice.csr
    ```
    Set fields as desired. CN=alice, challenge pass phrase is **_challengeme_**.
3. Alice then sends the CSR to the CA
    ```
    openssl x509 -req -in alice.csr -CA ca.crt -CAkey caprivate.key -CAcreateserial -out alice.crt -days 365 -sha256
    ```
    This step is performed by the CA, not by Alice. The CSR is signed with the private key and the certificate of the CA. As a result Alice's certificate is created and must be securely sent back to her.
   
A first test:
```
$ curl -ik --cert alice.crt:alice12345 --key aliceprivate.key "https://localhost:8443/greeting?name=Alice"
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Fri, 01 Mar 2019 20:03:04 GMT

{"id":2,"content":"Hello, Alice"}
``` 
### Creating client keystore and truststore
First need to trust the CA certificate
```
keytool -import -file ca.crt -alias CA -keystore alice_truststore.jks
```

Use _Keytool_ to create the truststore and _Openssl_ to create the truststore as before. The keystore currently requires to have th same password as the private key.
```
keytool -import -file alice.crt -alias ALICE -keystore alice_truststore.jks
openssl pkcs12 -export -in alice.crt -inkey aliceprivate.key -certfile alice.crt -out alice_keystore.p12
```

