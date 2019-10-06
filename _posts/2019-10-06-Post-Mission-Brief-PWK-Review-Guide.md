Penetration with Kali (PWK) Review Guide after having completed 90 lab. Resources and tips to help fellow hackers develop & execute a plan for attacking the lab network.

----------

Legal Usage:
*The information provided by execute@will is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.*

*By continued reading, you acknowledge the aforementioned user risks/responsibilities.*

----------

# Abstract

This overview will be a 10,000ft internal view of Penetration with Kail (PWK )course/lab and explain procedures, contain personal thoughts and methodologies used throughout the 90 day training window purchased. This is to be used as a resource guide and will NOT contain any specifics pertaining to actual machines in the lab.

![source: b24.net/MissionAnatomy.htm](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570314291876_image.png)



# Initial Impressions:

Penetration with Kali (PWK) course provided an environment to develop and hone in experience to aid in the completion of the Offensive Security Certified Professional (OSCP) certification. 

Many throughout the web liken a comparison to Hackthebox (HTB) to which there are some similarities but having completed a 90 day training window I can attest that vaguely speaking I find HTB more challenging in that the rabbit holes are easier to find yourself in. Having practiced with multiple [Vulnhub](http://www.vulnhub.com) machines, countless hours of “his greatness” [IppSec YouTube](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) videos and hours spend reading and researching in preparation

*Goal: Keep it simple develop foundation and build upon and grab every piece of prep material I can find along the way to help. Step two don’t get crushed.*

Prior reading material/Courses
- Ethical Hacking - Cybrary
- Advanced Ethical Hacking - Cybrary

- Linux Basics for Hackers - Occupytheweb - https://amzn.to/2OpdJ4c
- Hacking The Art of Exploitation - Jon Erickson - https://amzn.to/31SNiYw
- The Shellcoder’s Handbook - Chris Anley - https://amzn.to/2Oo0l09
- The Web Application Hacker’s Handbook 2nd Edition - Dafydd Stuttard - https://amzn.to/354e9Db
- OWASP Top 10 - OWASP - https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
- Red Team Field Manual - Ben Clark - https://amzn.to/2OmOfV7
- The Hacker Playbook - Peter Kim - https://amzn.to/2VizUL6
- The Hacker Playbook 2 - Peter Kim - [https://amzn.to/2Mn8Vdg](https://amzn.to/2Mn8Vdg)
- The Hacker Playbook 3 - Peter Kim - https://amzn.to/31PHxLl
- Violent Python - TJ O’Connor - https://amzn.to/31U4I7e
- Penetration Testing - Georgia Weidman - https://amzn.to/2OkEKG5


# System Setup / Configuration


![](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570388348159_hardware.jpg)


**Hardware:** 
- 2013 Macbook Pro - https://amzn.to/2AKcJ2D
- 2.4 GHz Intel Core i5 - 8GB DDR3
- 1TB Samsung 970 - https://amzn.to/2ALF9cD
- Undervolted with Volta 

- Custom Small Form PC (sfpc)
- DAN A4 Case - https://www.sfflab.com/products/dan_a4-sfx
- Ryzen 7 1700 (would recommend 3rd gen) -  https://amzn.to/31LNzfU
- TridentZ RGB 32GB DDR4 3200 -  https://amzn.to/35cffws
- Samsung 4TB  -  https://amzn.to/2MamWdS
- MSI GTX 1070 - https://amzn.to/2LMUlwq

- x1 Pwnogatchi via @evilsocket: [](https://twitter.com/pwnagotchi)https://twitter.com/pwnagotchi

**Software:**
- VMware Fusion (mac) - https://amzn.to/2VdouIq
- VMware Workcenter (Windows10) 
- Virtual Box (mac/Windows10)

[Offensive Security Custom Kali Image](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/) - Would highly recommend using it and customizing it to your own needs as new distros can cause issues while performing PWK exercises.

Exported VMware image to OVA imported to Virtual Box. Personally prefer Virtual Box to VMware do to the simplicity and consistency. Maintaining image across multiple virtualization software also aid in redundancy when dealing with disaster recovery.



# Managing VMs and Disaster Recovery

With my main PWK image being used within VMware to connect to Offsec VPNs for the course as mentioned keeping multiple backups is KEY throughout this course. Horror stories of people losing data and having to start from scratch. This doesn’t have to be you. 

Real Life Example:
*Salute to @Djax_Alpha misery - “another one bites the dust”*

![](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570198971462_image.png)


*source:* https://twitter.com/Djax_Alpha/status/1174436036417597440

These are the steps I used to safeguard and backup my image:

Firstly, as soon as you have configured the PWK image 

- Take an immediate snapshot.
- Export an OVF to an external thumb drive.
- Set a reminder on your phone to every week to **at minimum** perform the off system backup.
- Put thumb drive in the same location you would store your passport. (known secure location)

*Personally it didn’t take not more then 2 weeks into PWK that I encountered my first full system loss. Woke up fired up VMware Kali was toast and would not boot.*

## Notes Taking

An essential skill for any aspiring pentester. Anyone with the knowledge of how to exploit vulnerabilities but in the end it’s the management of information and being able to write a detailed report of an engagement that separates the Professionals from the rest.

Watching many saving their notes with a popular application CherryTree ([Link](https://www.giuspen.com/cherrytree/)) there was one fundamental problem with keeping notes on the application in the VM — Image Dies, so goes your notes unless backed up.


![Image: cherrytree application via giuspen.com](https://www.giuspen.com/images/cherrytree-main_window_text.png)


OSCP [Michael LaSalvia](https://www.youtube.com/user/genxweb) of DigitalOffensive had a great video explaining on how to setup rsync to backup cherrytree files to a google drive account that I’ll link below:

![https://youtu.be/BvLMQMjV9YE](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570388638977_image.png)

*source:* https://youtu.be/BvLMQMjV9YE

*Reiterating, this is a solution but not my personal as I’m not a fan of relying solely on the VM image.*


## exec Notes Backup Solution
- Download the CherryTree application for windows - [cherrytree_0.38.9_setup.exe](http://www.giuspen.com/software/cherrytree_0.38.9_setup.exe)
- Setup an OSCP folder locally
- Backup folder with Google Backup and Sync application - [Link](https://www.google.com/drive/download/backup-and-sync/)

The cherrytree application functions exactly as is does within the VM and now you have the application in a windows 10 environment that is inherently more stable. Following more or less the same framework by utilizing the Google Back up and Sync application your files are saved automatically in the background to the cloud. 


## Target Engagement Notes

**Enter -** [**Paper by Dropbox**](/)

![Dropbox Paper Example](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570212715010_image.png)


I highly recommend that you take the same approach to off machine saving of target notes. I found that utilizing Dropbox Paper as an OUTSTANDING solution. Paper, uses the markdown language for streamlined organization with code blocks but also has a search function that parses through all notes you have taken. Simple put GAMECHANGER!

I cannot express the full extent of how easy paper made the not taking process and it was completely backup to the cloud. (connection of other people’s computers)

YouTube Dropbox Tour: https://youtu.be/BVCe8v7opUs

![https://youtu.be/BVCe8v7opUs](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570388599475_image.png)



# Information / Tools (binaries) Management

Throughout the course you will be downloading/cloning many GitHub repositories and may have found a treasure trove of information from others in the same pursue. Initially, I felt like a hoarder


![teenage mutant ninja turtles pizza GIF via giphy](https://media1.giphy.com/media/hQzRjWvEEEKlO/giphy.gif?cid=790b761131c5e7ed41c1c108de5223e605a490cffd8f2047&rid=giphy.gif)


Every piece of everything I began trying to find a place for it with the “I might need later” tell well… It became too much. Saving links from twitter to Google Keep (note taking application) just became overwhelming. 

*To this day still don’t have quite a solution for how to cut through all these weeds.*


- Takeaway

Save important commands and syntax to Dropbox Paper and use a hierarchy structure. Lean on the search feature to parse through notes.

![](https://paper-attachments.dropbox.com/s_3FD52BCF06F126AFA200877FF5BF78377F0D81036A5EE80B9F6587F992A2342E_1570212466796_image.png)


 **Very important that you ensure your files are only visible to “Only you”**



## Attack Methodology 

My initial thoughts after having connected the VPN server was “Ok, now what…” a bit of an overwhelming feeling that soon will subside as soon a you just remember this is YOUR training battlefield.

Network recon:
A collection of recon scripts that were clearly laid out and offered tailored enumeration should you so be inclined. At the very least worth checking out

Ucki's Recon & Enumeration Pack - https://github.com/ucki/URP
verison v.01 - https://github.com/ucki/URP-T-v.01


## Structure
1. Recon
2. Enumeration of all version numbers found
3. Search version number vulnerabilities with both duckduckgo and Google (discovered variations in search results)
4. Establish foothold && a secondary shell (backup)
5. Interpret your environment
6. Search for vulnerable processes
7. Elevate - “*insert song* Drake - Elevate”
8. Run proof scripts
9. Document steps taken to achieve this point — **important** 

🎁 *Gift to those who have gotten this far — hang on to for safe keeping: https://guif.re/*



# Final Thoughts
![training pilot GIF](https://media2.giphy.com/media/7SnpfYuPjxzK8/giphy.gif?cid=790b7611c4ffd11496ff29ca53c17a963843c7f590e3cc40&rid=giphy.gif)


Penetration with Kali was an experience to say none the least. The levels of frustrations hit absolute peek levels and the 90 days seemed to have breezed by.

Honest advice, the course at times could be overwhelming but the will to endure needs to be more. Treating the targets as CTF’s is not the way to approach this situation. Your job is to learn how to discover vulnerabilities and exploit them and manage the documentation. It is here within the lab you hone that systematic approach. 

Personally, I achieved 41/50 targets across all networks and while you can spend your time fighting against the “Big 4” I personally left them for the end and only accomplished 2 of 4.

Lastly, do yourself a favor after you enter the lab plan to take breaks to manage your sanity. You will quickly get burnt out and I found that taking time to physically work out help balance the mental strain — Trust me on this one.

Believe in yourself.

-Executeatwill

