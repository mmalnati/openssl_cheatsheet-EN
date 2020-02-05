<h1>keytools commands</h1>

> Note: (In case you don't have keytools, go to /usr/java/server-jdk/jre/bin/keytool or use ps aux |grep java to see where java is installed)
<h4View the content of the certificate</h4>

```keytool -printcert -v -file certificate.crt```

<h4>View the list of the certificates in the keystore</h4>

```keytool -list -v -keystore keystore.jks```

<h4>View a certificate in the keytools from the alias</h4>

```keytool -list -v -keystore keystore.jks -alias alias_certificate```

<h4>Add a certificate into a keystore</h4>

```keytool -import -trustcacerts -file certificate.crt -alias alias-cert -keystore keystore.jks```

<h4>Add certificate without confirmation [y/n]</h4>

```keytool -import -trustcacerts -file certificate.crt -noprompt -alias alias-cert -keystore keystore.jks```

> You can add the option -storepass at the end, and then the key to add the password directly, or without it so it ask you later to write it.
<h4>To export a certificate in the keystore, from an alias</h4>

```keytool -export -alias alias-cert -file certificate.crt -keystore keytools.jks```

> Search the alias before.</h4>

<h4>Export a certificate from a keystore</h4>

```keytool -export -alias alias-cert -keystore keystrore.jks -rfc -file certificate.crt -storepass clave```

<h4>Export the key to a pkcs12 file</h4>

```keytool -v -importkeystore -srckeystore keystore.jks -srcalias alias-cert -destkeystore myp12file.p12 -deststoretype PKCS12```

<h1>openssl commands</h1>
<h4>Extract from a pkcs12 file the key</h4>

```openssl pkcs12 -in myp12file.p12 -out private.key```

<h4>View the content of the .pfx file</h4>

```openssl pkcs12 -info -in archivo.pfx```

<h4>View the Certificate Signing Request (CSR) information</h4>

```openssl req -text -noout -verify -in CSR.csr```

<h4>Check the private key</h4>

```openssl rsa -in privateKey.key -check```

<h4>View certificate information</h4>

```openssl x509 -noout -text -in certificate.crt```

<h4>View the PKCS#12 information(.pfx or .p12)</h4>

```openssl pkcs12 -info -in keyStore.p12```

<h4>View md5 of the certificate</h4>

```openssl x509 -noout -modulus -in /etc/ssl/ca/certs/ca.crt | openssl md5```

<h4>Check md5 of the key</h4>

```openssl rsa -noout -modulus -in /etc/ssl/ca/private/ca.key | openssl md5```
<h4>Check csr information</h4>

```openssl req -noout -modulus -in CSR.csr | openssl md5```

<h4>Extract a certificate from a web site and then  export to file .crt</h4>

```openssl s_client -showcerts -connect google.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >certificate.crt```

<h4>Check md5 from a certificate</h4>

```openssl x509 -noout -fingerprint -md5 -inform pem -in certificate.crt```

<h4>Create a pfx file with a certificate and a key</h4>

```openssl pkcs12 -export -out archivo.pfx -inkey private.key -in certificate.crt```
<h4>Create a pfx file with the CA and the intermediate CA</h4>

```openssl pkcs12 -export -out archivo.pfx -inkey private.key -in certificate.crt -in intermediate.crt -in rootca.crt```
<h4>View the information of multiple certificates from a single file</h4>

```openssl crl2pkcs7 -nocrl -certfile CHAINED.pem | openssl pkcs7 -print_certs -text -noout```

<h4>Show the subject and issuer and issuer of each certificate</h4>

```openssl crl2pkcs7 -nocrl -certfile cabundle.ca | openssl pkcs7 -print_certs -text -noout```

<h4>Fix a certificate when the keytool shows an error to import in the keystore</h4>

```openssl x509 -in broken.pem -out correct.pem```
