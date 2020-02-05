<h1>Comandos keytools</h1>

> Nota: (En caso de que no tenga keytools, desde el directorio /usr/java/server-jdk/jre/bin/keytool o un ps aux |grep java y ver donde está instalado java)
<h4>Ver contenido de certificado con keytools</h4>

```keytool -printcert -v -file certificate.crt```

<h4>Ver los certificados que hay dentro de un jks</h4>

```keytool -list -v -keystore keystore.jks```

<h4>Ver un certificado a partir del alias</h4>

```keytool -list -v -keystore keystore.jks -alias alias_certificado```

<h4>Agregar un certificado a un keystore</h4>

```keytool -import -trustcacerts -file certificate.crt -alias alias-cert -keystore keystore.jks```

<h4>Agregar certificado sin que pida confirmación [y/n]</h4>

```keytool -import -trustcacerts -file certificate.crt -noprompt -alias alias-cert -keystore keystore.jks```

> Se puede agregar la opción -storepass al final y luego la clave, para ingresar directamente la clave, o sin la opción para que luego la pida.
<h4>Para exportar un certificado que ya está en el jks, se debe correr el siguiente comando</h4>

```keytool -export -alias alias-cert -file certificate.crt -keystore keytools.jks```

> Buscar antes el alias del certificado.</h4>

<h4>Exportar certificado de un jks</h4>

```keytool -export -alias alias-cert -keystore keystrore.jks -rfc -file certificate.crt -storepass clave```

<h4>Exportar a pkcs12 la key</h4>

```keytool -v -importkeystore -srckeystore keystore.jks -srcalias alias-cert -destkeystore myp12file.p12 -deststoretype PKCS12```

<h1>Comandos openssl</h1>
<h4>Extraer del pkcs12 la key</h4>

```openssl pkcs12 -in myp12file.p12 -out privatekey.key```

<h4>Ver contenido de archivo .pfx</h4>

```openssl pkcs12 -info -in archivo.pfx```

<h4>Chequear Certificate Signing Request (CSR)</h4>

```openssl req -text -noout -verify -in CSR.csr```

<h4>Chequear  private key</h4>

```openssl rsa -in privateKey.key -check```

<h4>Chequear certificate</h4>

```openssl x509 -noout -text -in certificate.crt```

<h4>Chequear archivo PKCS#12 (.pfx or .p12)</h4>

```openssl pkcs12 -info -in keyStore.p12```

<h4>Chequear md5 de .crt</h4>

```openssl x509 -noout -modulus -in /etc/ssl/ca/certs/ca.crt | openssl md5```

<h4>Chequear md5 de .key</h4>

```openssl rsa -noout -modulus -in /etc/ssl/ca/private/ca.key | openssl md5```
<h4>Chequear csr</h4>

```openssl req -noout -modulus -in CSR.csr | openssl md5```

<h4>Extraer certificado de un sitio web y exportarlo a un archivo .pem</h4>

```openssl s_client -showcerts -connect google.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >certificate.crt```

<h4>Chequear md5 de certificado</h4>

```openssl x509 -noout -fingerprint -md5 -inform pem -in certificate.crt```

<h4>Crear pfx</h4>

```openssl pkcs12 -export -out archivo.pfx -inkey private.key -in certificate.crt```
<h4>Crear un pfx con la CA y el intermedio</h4>

```openssl pkcs12 -export -out archivo.pfx -inkey private.key -in certificate.crt -in intermediate.crt -in rootca.crt```
<h4>Ver los datos de varios certificados dentro de un mismo archivo</h4>

```openssl crl2pkcs7 -nocrl -certfile CHAINED.pem | openssl pkcs7 -print_certs -text -noout```

<h4>Muestra solo el subject e issuer de cada certificado</h4>

```openssl crl2pkcs7 -nocrl -certfile cabundle.ca | openssl pkcs7 -print_certs -text -noout```

<h4>Corregir un certificado cuando no lo toma keytools</h4>

```openssl x509 -in broken.pem -out correct.pem```
