---
published: true
---

Vulnhub virtual machine; OSCP prep box, and a very interesting one indeed. This box included a few hints and clues sprinkled around a web application which then pivoted to multiple user escalations along side decryption of cipher-text which led to eventual root.


----------

Legal Usage:
*The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risk/responsibilities.*


----------



Initial Setup Note: When booting this VM ensure you virtualization software uses the MAC address `08:00:27:A5:A6:76`  I probably spent way more time then I’d like to admit troubleshooting networking issues then I really should have. #fundamentalsofreading



Discover VM on network:

    netdiscover -r 192.168.56.0/24

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551037210803_image.png)



# Enumeration

Nmap Scan:

    nmap -sV -sC -oA nmap/fristileaks 192.168.56.109

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551037189296_image.png)


*robots.txt looks to have some interesting directories disallowed*

Navigate to webserver:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551037488278_image.png)


*Not my favorite color but we have a list of user names and a date of 2015.*

Users:


    @meneer, 
    @barrebas, 
    @rikvduijn, 
    @wez3forsec, 
    @PyroBatNL, 
    @0xDUDE, 
    @annejanbrouwer, 
    @Sander2121, 
    Reinierk, 
    @DearCharles, 
    @miamat, 
    MisterXE, 
    BasB, 
    Dwight, 
    Egeltje, 
    @pdersjant, 
    @tcp130x10, 
    @spierenburg, 
    @ielmatani, 
    @renepieters, 
    Mystery guest, 
    @EQ_uinix, 
    @WhatSecurity, 
    @mramsmeets, 
    @Ar0xA

*Might be helpful in the future.*


Source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551037770488_image.png)


*First clue, as we are to achieve root and box estimates 4hrs to complete.* 

Investigate robot.txt disallowed directories
http://192.168.56.109/cola

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038135894_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038154156_image.png)


Download locally to investigate for stenography 


    file 3037440.jpg

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038316751_image.png)

    strings 3037440.jpg

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038337930_image.png)


*Nothing such as .zip or anything is standing out as of now.*

Other `/sisi/` and `/beer/` both contain links to the same image.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038499184_image.png)


Thinking all these directories have some type of drink in the name and we were told to “keep calm and drink fristi” maybe a `/fristi/` directory exists.

Navigate to `/fristi/`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038632852_image.png)


*attempt basic logins admin/admin, root/password… etc first.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038677022_image.png)


*Met with a whole lot of “wrong username or password”*


SQL-injection time

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038857957_image.png)



![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038677022_image.png)


*Content filtering is occurring, good job webadmin.*

View source:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551038911760_image.png)


*well hello base64 encoded image.*

Decode base64:
create file with base64

    
    iVBORw0KGgoAAAANSUhEUgAAAW0AAABLCAIAAAA04UHqAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
    jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAARSSURBVHhe7dlRdtsgEIVhr8sL8nqymmwmi0kl
    S0iAQGY0Nb01//dWSQyTgdxz2t5+AcCHHAHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixw
    B4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzkCwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL5kc+f
    m63yaP7/XP/5RUM2jx7iMz1ZdqpguZHPl+zJO53b9+1gd/0TL2Wull5+RMpJq5tMTkE1paHlVXJJ
    Zv7/d5i6qse0t9rWa6UMsR1+WrORl72DbdWKqZS0tMPqGl8LRhzyWjWkTFDPXFmulC7e81bxnNOvb
    DpYzOMN1WqplLS0w+oaXwomXXtfhL8e6W+lrNdDFujoQNJ9XbKtHMpSUmn9BSeGf51bUcr6W+VjNd
    jJQjcelwepPCjlLNXFpi8gktXfnVtYSd6UpINdPFCDlyKB3dyPLpSTVzZYnJR7R0WHEiFGv5NrDU
    12qmC/1/Zz2ZWXi1abli0aLqjZdq5sqSxUgtWY7syq+u6UpINdOFeI5ENygbTfj+qDbc+QpG9c5
    uvFQzV5aM15LlyMrfnrPU12qmC+Ucqd+g6E1JNsX16/i/6BtvvEQzF5YM2JLhyMLz4sNNtp/pSkg1
    04VajmwziEdZvmSz9E0YbzbI/FSycgVSzZiXDNmS4cjCni+kLRnqizXThUqOhEkso2k5pGy00aLq
    i1n+skSqGfOSIVsKC5Zv4+XH36vQzbl0V0t9rWb6EMyRaLLp+Bbhy31k8SBbjqpUNSHVjHXJmC2Fg
    tOH0drysrz404sdLPW1mulDLUdSpdEsk5vf5Gtqg1xnfX88tu/PZy7VjHXJmC21H9lWvBBfdZb6Ws
    30oZ0jk3y+pQ9fnEG4lNOco9UnY5dqxrhk0JZKezwdNwqfnv6AOUN9sWb6UMyR5zT2B+lwDh++Fl
    3K/U+z2uFJNWNcMmhLzUe2v6n/dAWG+mLN9KGWI9EcKsMJl6o6+ecH8dv0Uu4PnkqDl2rGuiS8HK
    ul9iMrFG9gqa/VTB8qORLuSTqF7fYU7tgsn/4+zfhV6aiiIsczlGrGvGTIlsLLhiPbnh6KnLDU12q
    mD+0cKQ8nunpVcZ21Rj7erEz0WqoZ+5IRW1oXNB3Z/vBMWulSfYlm+hDLkcIAtuHEUzu/l9l867X34
    rPtA6lmLi0ZrqX6gu37aIukRkVaylRfqpk+9HNkH85hNocTKC4P31Vebhd8fy/VzOTCkqeBWlrrFhe
    EPdMjO3SSys7XVF+qmT5UcmT9+Ss//fyyOLU3kWoGLd59ZKb6Us10IZMjAP5b5AgAL3IEgBc5AsCLH
    AHgRY4A8CJHAHiRIwC8yBEAXuQIAC9yBIAXOQLAixwB4EWOAPAiRwB4kSMAvMgRAF7kCAAvcgSAFzk
    CwIscAeBFjgDwIkcAeJEjALzIEQBe5AgAL3IEgBc5AsCLHAHgRY4A8Pn9/QNa7zik1qtycQAAAABJR
    U5ErkJggg==

Decode:

    cat b64code | base64 --decode

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040296218_image.png)


*File has a header of PNG. lets pipe this decode into a png file*


    cat b64code | base64 --decode > decode.png

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040380560_image.png)


*Well this is turning into a bit of a Drake “keke” song.*
image resolves to `keKkeKKeKKeKkEkkEk`

Since `eezeepz` was the one that left the message let try to login

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040502167_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040543886_image.png)


*We are in like fine swimwear! and upload file based off php lets try and upload a reverse shell.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040605963_image.png)


attempt to upload shell.php

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551040779437_image.png)


*we will need to disquise our shell as an image.*

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041111474_image.png)


*Made modifications to file name, content-type and added GIF89a;*

File filer bypassed and uploaded to `/uploads/` directory

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041193963_image.png)


Ensure listener is setup

    nc -lvnp 9000

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041248243_image.png)



# SHELL/RCE

Launch shell.php.gif

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041284039_image.png)

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041305269_image.png)



upgrade partial shell to full tty
Python method:

    python -c 'import pty; pty.spawn("/bin/bash")'
    press cntl+z 
    stty raw -echo
    fg (enter)
![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041611360_image.png)



# Priv-Esc

Start the quest to enumerate and elevate privileges on box.

    uname -a

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041729906_image.png)


search for vulnerabilities based off the 2.6.32 kernel



    searchsploit 2.6.32

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551041802626_image.png)


*looks like we found some priv esc code. — anddddd this has turned out not to be helpful.*

Running my enum scripts:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551043047977_image.png)


*Interesting avenues to take.* 

Continue Enumerating User Home directories:
Found in eezeepz a note.txt

    bash-4.1$ cat notes.txt
    Yo EZ,
    
    I made it possible for you to do some automated checks,
    but I did only allow you access to /usr/bin/* system binaries. I did                                                                  
    however copy a few extra often needed commands to my
    homedir: chmod, df, cat, echo, ps, grep, egrep so you can use those                                                                   
    from /home/admin/
    
    Don't forget to specify the full path for each binary!
    
    Just put a file called "runthis" in /tmp/, each line one command. The                                                                 
    output goes to the file "cronresult" in /tmp/. It should
    run every minute with my account privileges.
    
    - Jerry
    

*Jerry left this not to add files to /tmp/run that get run as his account.*

Lets input a reverse shell into the directory and see if we can elevate our privileges to jerry.
 
 Creating Perl-Reverse-Shell
 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551044611692_image.png)


*Made modifications needed.*

Setup new listener on 9001

    nc -lvnp 9001

download script to `/tmp` 

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551044781520_image.png)


Append the perl script to a new file name `runthis`

    echo "/usr/bin/perl /tmp/prs.pl" > runthis

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551045695458_image.png)


We are now Admin

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551045740129_image.png)


import new tty

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551045817293_image.png)


as in our previous encounter the home directory aided in our escalation as to now investigate `/home/admin`


![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551045942759_image.png)


*Interesting files exist here* `*cryptedpass.txt*` , `cryptpass.py` and `whoisyourgodnow.txt`.

Cat interesting files:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551046025567_image.png)


*seems to be encoded in rot13 based off the python script.*

Reconstructing the cryptpass.py to decode

    #Enhanced with thanks to Dinesh Singh Sikawar @LinkedIn
    import base64,codecs,sys
    
    def encodeString(str):
        decode = codecs.decode(str[::-1], 'rot13')
        return base64.b64decode(decode)
    
    cryptoResult=encodeString(sys.argv[1])
    print cryptoResult

run the scripts

    python cryptpass.py =RFn0AKnlMHMPIzpyuTI0ITG
    python cryptpass.py mVGZ3O3omkJLmy2pcuTq

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551046663680_image.png)


*we now have plain-text passwords.*

Utilizing password to `su` to fristigod

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551046813314_image.png)


quick `sudo -l` to see what fristi god is capable of doing:

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551046893442_image.png)


*we have a* `*.secret_admin_stuff/doCom*` file which looks very interesting.

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551047029495_image.png)


Checking the `.bash_history`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551047098916_image.png)


*we see a lot of movement pertaining to a user* `*fristi*`


# Root

Attempt to run the doCom as `fristi` user.

    sudo -u fristi /var/fristigod/.secret_admin_stuff/doCom

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551047298486_image.png)


well well….

running `doCom` as usage indicates but calling `/bin/sh`

![](https://d2mxuefqeaa7sj.cloudfront.net/s_3BF4EC4CE04E4C4A36C4F49F58A516E95BCB111A4330487626F5EB5298F8AFD7_1551047416988_image.png)


Bring me the Root!

-exec
