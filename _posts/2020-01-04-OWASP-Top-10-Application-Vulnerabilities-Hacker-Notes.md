Detailed overview of the OWASP Top 10 utilizing OWASP Juiceshop VM to cover application vulnerabilities.

----------

Legal Usage: The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.

By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------

Based off TheCyberMentor amazing Udemy course available at https://www.udemy.com/course/practical-ethical-hacking/


## OWASP Top 10 Testing Checklist

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577979734179_image.png)


source: https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf

Link: https://www.owasp.org/index.php/Testing_Checklist
Cheat Sheets: https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
Cheat Sheets: https://cheatsheetseries.owasp.org/


Major Headings Overview:

- Information Gathering
- Configuration and Deployment Management Testing
- Identity Management Testing
- Authentication Testing
- Authorization Testing
- Sessions Management Testing
- Data Validation Testing
- Error Handling
- Cryptography
- Business Logic Testing
- Client Side Testing

**Evolution of OWASP Top 10 2013 vs 2017**

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577979837320_image.png)


source: https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf


**OWASP Testing Checklist Excel .xlsx**
Link: https://github.com/tanprathan/OWASP-Testing-Checklist

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577980121481_image.png)


**OWASP Testing Guide PDF**
Link: https://www.owasp.org/images/1/19/OTGv4.pdf

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577980254226_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577980366933_image.png)

- Web Application Security Testing should use this PDF in accordance with the .xlsx


## Installing OWASP Juiceshop

Requirements: Docker

**Installing Docker on Kali**
installer reference link: https://medium.com/@airman604/installing-docker-in-kali-linux-2017-1-fbaa4d1447fe

Add Docker PGP key:

    curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981218687_image.png)


Add repositoriy (in my case its arch=x86)

    echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' > /etc/apt/sources.list.d/docker.list

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981276014_image.png)


Apt update

    apt update

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981288366_image.png)


Install docker-ce

    apt install docker-ce

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981326745_image.png)


**Download OWASP Juiceshop**
Vulnerable website - Learning tool for OWASP Top 10.
Link: https://github.com/bkimminich/juice-shop
Walkthrough Link: https://bkimminich.gitbooks.io/pwning-owasp-juice-shop/content/


Docker Container Install

    Install Docker
    Run docker pull bkimminich/juice-shop
    Run docker run --rm -p 3000:3000 bkimminich/juice-shop
    Browse to http://localhost:3000 (on macOS and Windows browse to http://192.168.99.100:3000 if you are using docker-machine instead of the native docker installation)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981989546_image.png)


*NOTE: Should you ever restart/reboot remember to start docker service again with* `*service docker start*`



- Goal should be to work through “Part II - Challenge hunting” off the gitbook.io

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1577981856619_image.png)



**Installing FoxyProxy - Burp Suite**
Link: https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028334326_image.png)

- After installed - Configuring FoxyProxy to work with Burm

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028411455_image.png)

- Adding Burp Suite to foxy proxy via “add”
![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028476066_image.png)

- Add localhost and port 8080 - I changed my color to Orange for Burp
![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028613808_image.png)

- Now we can quickly turn on/off Burp Suite proxy

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028691314_image.png)

- Import Burp Certificate to Firefox

Navigate to: `http://burp`
Click CA Certificate - Download

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028900710_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028923490_image.png)

- Install Certificate

Click Menu > Preference

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578028982620_image.png)

- Type “Certificates” into search and click “View Certificates” > “Import”

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578029032996_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578029068982_image.png)

- Import Downloaded `.der`

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578029130797_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578029148538_image.png)




## Attacking OWASP Juiceshop

**Setting Juiceshop as target scope**

- Adding `localhost:3000` as target scope and enable “show only in-scope items”

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578030714309_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578030729339_image.png)



- Investigate unauthenticated side

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578030813495_image.png)


Automated Scanners in reality on pick up about 10% of vulnerabilities.
 

- Adjust Proxy > options “Intercept Client Request” and “intercept Client Responses”

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578031062042_image.png)


**Intruder Faster Alternative - Turbo Intruder**
As intruder only allows for 1 thread on the Community Edition of Burp Suite Turbo Intruder expands the capability.  ****


- Install Turbo Intruder on Burp Suite from BApp store

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578031423028_image.png)



## Injection Attacks
- Navigate to: `http://localhost:3000/#/score-board`
- “Hide all” then Select “Injection”

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A1-Injection


![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578035735586_image.png)


**Login Admin**

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578035913951_image.png)


Link: `http://localhost:3000/#/login`


- Test Login with captured request - send to Repeater:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578037225421_image.png)

- Within Repeater we are faced with an “Invalid email or password”

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578037317984_image.png)


Submitted the SQL command could be:

    SELECT * FROM Users WHERE email='test';

Where moving to add an extra `'` within the email we can result in a SQLITE ERROR and see the exact SQL command.

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578037563034_image.png)


Modifying the statement to end in a true statement:

    SELECT * FROM Users WHERE email='test' OR 1=1; --;


- Using an SQL injection to bypass the login

Email: `test' OR 1=1`
Password: Password

The SQL injection allows for a true statement which is then processed by the application as a valid login:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578037036804_image.png)
![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578037103751_image.png)





## Broken Authentication

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A2-Broken_Authentication


- Application Vulnerable

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578043967020_image.png)


*souce: OWASP Top 10 2017 A2 Broken Authentication*

**Testing for Broken Authenication**

- When submitting a login field we want to be aware of the response if its leaking information such as “invalid email or password”

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578051561413_image.png)

- “Forgot my password”

In this situation we are facing an area where we can enumerate users as the security question did not change:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578051659267_image.png)


From the previous attack we found the user email of admin as `admin@juice-sh.op` to which the fields open based off the admin email.

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578051993396_image.png)


Testing for session fixation involves creating an account and logging in and based on the cookie that is given if we logout we should not be able to use that same cookie to login again.



## Sensitive Data Exposure
- Extracting data that is available who expose the web-server


![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578052448089_image.png)


Link: https://www.owasp.org/index.php/Top_10-2017_A3-Sensitive_Data_Exposure

**Juiceshop Sensitive Data Exposure**
Location: `/ftp` was discovered and contains files that should not be facing the internet:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578066043813_image.png)

- kdbx - password storage




## XML External Entities (XXE) Overview

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578066565045_image.png)

- using a system entity within XML and using against a target

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A4-XML_External_Entities_(XXE)

XML Formatting Example

    <?xml version="1.0" encoding="ISO-8859-1"?>
    <gift>   # declare root element
            <To>Frank</To>   # children element
            <From>Exec</From>  # children element
            <Item>Pokemon Cards</Items>    # children element
    </gift>
- using entities we can give multiple gifts
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE gift [                 # document type definition (DTD)
            <!ENTITY from "Exec&Amber"> # allows inclusion of special characters
    ]>
    <gift>   # declare root element
            <To>Frank</To>   # children element
            <From>&from;    Exec+Amber</From>  # gift from multiple people
            <Item>Pokemon Cards</Items>    # children element
    </gift>

with this thought process we could use forward slashes and extract a file from inside the entity

**Payloads**
Link: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection


- Classic XXE
    <?xml version="1.0" encoding="ISO-8859-1"?>
      <!DOCTYPE foo [  
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>

 *using SYSTEM as an entity we can have it result in parser is external and to store content into it. When foo is called it calls the* `*/etc/passwd*`
 
 
 
**Attacking XXE**
save the payload locally as `test.xml`

    <?xml version="1.0" encoding="ISO-8859-1"?>
      <!DOCTYPE foo [  
      <!ELEMENT foo ANY >
      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>


- Create a new user on Juiceshop

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578068540749_image.png)

- login to account - navigate to `/#/complain` to which we will take adavange of the “Browse” upload feature and upload the `test.xml` + capture request

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578115137001_image.png)

*should the xxe had been successful in our repsonse window we would see a print out of the* `*/etc/passwd*` to which in this case we do not.

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578116064147_image.png)


**Mitigating XXE**

- Disable xml entities (DTEs)



## Broken Access Control
- If there was an `/admin` panel when normal user should not have access too.
- changeing `?=5` to `?=6` and return another accounts information -  Insecure Direct Object Reference (IDOR)

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A5-Broken_Access_Control


**Attacking** **Broken Access - Juiceshop**

- adding information from another user.

Forged Feedback: Post some feedback in another users name.

Under Customer Feedback

- leave bad review
- right click inspect elements


![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578122369646_image.png)


we have a “hidden” id event occuring - deleteing the word hidden results in a user id field box appearing and changing 17 to 1 (admin):

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578122450356_image.png)

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578122545862_image.png)


*This is a prime example of broken access control.*



## Security Misconfiguration
- If something was configured incorrectly in anyway is considered a misconfiguration
- Default credential left unchanged is an example
- Application throwing detailed/verbose error messaging
- Unnecessary ports open
- Basically a “catch all” for vulnerabilities 

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A6-Security_Misconfiguration



## Cross Site Scripting (XSS)

**Three types of Cross Site Scripting**

- Reflected XSS - Popup / never stored on server / server reads responds - client side
- Stored XSS - Stored payload on the web server - server side
- DOM XSS - Document Object Model (Javascript) - client side 

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A7-Cross-Site_Scripting_(XSS)

**Reflected XSS Attack**

- Requires social engineering - stealing a cookies from a user and redirected

create a php script

    index.php
    
    <?php
    $username = $_GET['username']
    echo "High $username!";
    ?>

With this php script when accessing `index.php?username=exec` the response on the site will be Hi Exec.

Alerting Script

    index.php?username=<script>alert(1)</script>

Javascript pop up an window with alert one into the field.

**Stored XSS**
If in a situation where `<script>alert(1)</script>` is left on a page and having the alert popup every time someone is to access the page. 

In a different situation the stored xss could have a cookie stealing function and an attacker could then utilized that cookie in a forged request.

**DOM based XSS**
Blog link: https://www.scip.ch/en/?labs.20171214


- Bit complex of an attack (source / sink)
- source input malicious code
- Sink executes code
- Least found out in the wild
- Client side attack that will require social engineering like reflective XSS

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578133502872_image.png)


source: https://www.scip.ch/en/?labs.20171214

Adding a `<img src=``"``test``"` `onerror=``"``alert(``'``XSS``'``)``"` will popup the XSS.

**Attack XSS**


- Reflective XSS

Within Juiceshop `/#/score-board` we can see the available XSS:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578133845016_image.png)

    Payload = <iframe src="javascript:alert(`xss`)"> 

Find a location to paste payload across the site testing within an an object “Banana Juice” posted as a review:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578134091734_image.png)


Doesn’t respond with the said popup.

Pasting the XSS payload into the search does proc a DOM XSS.

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578134183577_image.png)


Testing in other areas such as the user profile with a moral being to attack any field that available:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578134371426_image.png)


*To which under the Username: some form of filtering is occurring as it never fully added the payload to the username.*



- Stored XSS

Regular user could leave something on the page that steal the administrators cookie and allows for 


![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578135130574_image.png)

    Payload = <script>alert(`xss`)</script> 

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578135216017_image.png)


*bypassing the username we see that the filtering and testing what could be done to get around filter.*

results in adding script again allowing it to be filtered but letting it still exist in its full format: 

    <<script>ascript>alert(`xss`)</script> 

To which <script>a will be removed by the filter but the alert will still be sent to the server.

now returning to the account profile page we have a stored xss:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578135504000_image.png)



- Using Intruder to perform attack against xss

Capture the xss “Set Username” with Burp and Send to Intruder

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578136054744_image.png)


From Intruder tab clear all feilds and select only the xss location and press add:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578136125659_image.png)


Add payloads which can be found by googling: xss payloads
Payloads Link: https://github.com/Pgaijin66/XSS-Payloads/blob/master/payload.txt

Under the Payloads tab under intruder we can add / paste the payloads from the github page:

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578136253094_image.png)



- DOM XSS (has interactive tutorial)

**Mitigating XSS**

- cookies set as HTTP-Only and HTTP-Secure
- HTTP-Only prevent users from viewing cookies 
- XSS Header filtering

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578136439639_image.png)


**XSS Game (web application) for Testing**
Link: https://xss-game.appspot.com/

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578134527137_image.png)


Level 1: `<script>alert(``'``xss``'``)</script>`



## Insecure Deserialization 

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A8-Insecure_Deserialization


- Convert an object to a disk via a serialized and sent over a network. 
- Could be serialized with json, binary, xml, yml.
- Opposite process is de-serialized and executes it

**Mitigation of Deserialization**

- Do not accept serialization from un-trusted/unknown sources
- Tool: ysoserial 

![](https://paper-attachments.dropbox.com/s_47ABE09D1CB9E70832B547DB1A053F40CF14ED5D2061471E0EA66D4646A23675_1578137061966_image.png)


Github Link: https://github.com/frohoff/ysoserial



## Using Components with Known Vulnerabilities
- Identifying software that has not been upgraded or patched and leveraging that aspect

Burp Suite contains a few tools that can be used:

    BApps that can perform known vulnerability scans include:
    -Active Scan
    -Software Vulnerability Scanner
    -Java Deserialization Scanner



## Insufficient Logging & Monitoring
- Tracking is important and should be include on web servers (any/everything)

OWASP Link: https://www.owasp.org/index.php/Top_10-2017_A10-Insufficient_Logging%26Monitoring

