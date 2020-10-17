---
published: true
---
Journey and review of accomplishing the Offensive Security Certified Professional Exam (OSCP). Documenting the ups and downs creating an attack plan and colminating in achievement.

----------

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1601174324526_postoscplogo.jpg)

# Overview

The Offensive Security Certified Professional (OSCP) is more than just targeting boxes and popping shells. What you sign up for is a journey; one filled with fear, anguish, self-doubt, and frustration but rewarded with the resolve to overcome obstacles. Understandably, this path is not one for someone who is a dabbler. You WILL require a fire within and a drive to succeed that you might not know is inside of you. 

At the destination of this journey, you will be a different person. You are required to be one who has a mindset to look for solutions and preserver through adversity.

Impossible, no. 
Difficult, yes.

You are going to need to have an honest conversation with yourself. “Is this something I truly want?” and only you can honestly answer it.

## First Attempt
I had initially signed up for a 90 Day - Penetration with Kali (PWK) Lab and crossed the borders of all networks tackling box after box on the proverbial “struggle bus”. Leading me to accomplish a majority of the boxes but lacking that methodology needed.

*Key Takeaway: I failed to realize the purpose of the labs and was focused on an arbitrary number of boxes. I didn’t take into account that this is where you would practice targeting services and honing your skills. I treated the whole event as a Capture the Flag (CTF). This was a mistake.*

Jumping into the first exam attempt I choked. My mistakes from the labs became glaring. My Buffer Overflow (BOF) took close to 8hrs to accomplish. Scrambling notes trying to understand why things would not align. I just didn’t have the experience to truly understand what exactly was going on in a stack overflow. From one blunder to another to a complete loss of confidence. I felt the failure as a complete blow to my ego and my efforts as fruitless. I didn’t touch a box for 3 months.

![“Everyone has a plan 'till they get punched in the mouth” - Mike Tyson](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1602957508233_image.png)

enters depression and imposture syndrome… This is real and you should be very aware of these feelings. You must have the “why” dialed in to call upon in these times.

## Time to Rise Above 

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1601163642310_Full_F-22_Demo_Exclusive_Look_Inside_the_Raptor.gif)

*Key Takeaway: Have a plan for failure and understand it’s all part of the process. Remember F.A.I.L is simply the “first attempt in learning”.*

After taking some time to reflect and really dial in my personal “why” and we got back into the zone analyzing my weakness of stack overflows and developed a concrete methodology. I knew what I needed was more experience and so into the fire I went:

Full Course Immersion:
- Udemy - [Practical Ethical Hacking - The Complete Course](https://www.udemy.com/course/practical-ethical-hacking/)
- Udemy - [Windows Privilege Escalation for Beginners](https://www.udemy.com/course/windows-privilege-escalation-for-beginners/)
- Udemy - [Linux Privilege Escalation for Beginners](https://www.udemy.com/course/linux-privilege-escalation-for-beginners/)

- Virtual Hacking Labs - [30 Days](https://www.virtualhackinglabs.com/) (Only accomplished a handful boxes - PWK Lab reminiscent)
- TryHackMe - [Offensive Pentesting Path](https://tryhackme.com/path/outline/pentesting) (48hrs of tranining)

![](https://pbs.twimg.com/media/Eh05VAKXkAUeHIF?format=png&name=medium)

Buffer Overflow Training:
- TryHackMe - [Buffer Overflow Prep](https://tryhackme.com/room/bufferoverflowprep)
- TryHackMe - [Brainpan](https://tryhackme.com/room/brainpan)
- TryHackMe - [Sudo Buffer Overflow](https://tryhackme.com/room/sudovulnsbof)
- TryHackMe - [Gatekeeper](https://tryhackme.com/room/gatekeeper)
- TryHackMe - [Brainstorm](https://tryhackme.com/room/brainstorm)

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1602959370568_image.png)

I needed to sharpen up my stills and to buckled in for the ride. 

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1601163247500_VIOLENT_Super_Hornets_Carrier_Catapult_Takeoffs__Flight_Deck_Ops_USS_Theodore_Roosevelt.gif)

## Second Attempt

Leading up to scheduling the exam, I created a plan to review privilege escalation and to do that I would use Tib3rius courses:

- Udemy - [Windows Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/windows-privilege-escalation/)
- Udemy - [Linux Privilege Escalation for OSCP & Beyond!](https://www.udemy.com/course/linux-privilege-escalation/)

I put the exam three weeks into the future. First weekend leading to exam completing a course, second weekend accomplish second course. Third weekend, compile my lab notes and exercises completely formatted and ready for submission along with setup exam lab template (based off lab template).

*Key Takeaway: Step back and create your plan of success. Understand your weaknesses and attack them head on. Do yourself a favor and complete the lab exercises and document them in your lab report.*

It felt different right from the start. I had the methodology that I was missing I had the experience I so needed and all pulled together I aligned myself on the runway and SENT IT!

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1601163333767_VIOLENT_Super_Hornets_Carrier_Catapult_Takeoffs__Flight_Deck_Ops_USS_Theodore_Roosevelt+1.gif)

# Exam Setup

## Exam and Lab Reports
There is more to this than meets the eye. Make sure you thoroughly read all the instructions given to you by Offensive security (then read them again). My recommendation is to do as I did and use the standard template offered. ([Offensive Security Lab and Exam - Template](https://www.offensive-security.com/pwk-online/PWK-Example-Report-v1.pdf))

Could you use something else, sure. In the end you should be focused on NOT complicating your life not looking for ways to make it harder. 

*Key Takeaway: You have the ability to receive up to 5pts extra for completing the lab exercises. Imagine how you would feel if all you needed was those 5pts to pass? My flight instructor would drill into our heads “It’s better to be on the ground wishing you were in the air, than in the air wishing you were on the ground”.*

## System Shakedown

The days leading up to your exam you should perform a shake down of your system. Understand you will be taxing it with your VM, host system and the monitoring software used by offensive security. 

Take a snapshot of your VM you plan to use during the exam and make sure you have a plan for disaster.

Make sure your webcam is in working order and all drivers are preinstalled on system.

You will need Chrome browser and a few extensions that Offensive Security will give instructions on the setup. I personally use [Brave Browser](https://brave.com/) (and so should you) and had to make adjustments.

*“If you fail to plan, you are planning to fail!” - Benjamin Franklin*

# Post-Flight Briefing

## Final Thoughts

What you are tasked to do is not impossible. There are solutions to all problems and it’s up to you to use the resources and knowledge and find those solutions. You will become frustrated, you will have doubts, it will feel emotions rush through your veins as you inch closer and closer. I can’t give details about the exam but I can say believe in yourself and understand you have everything you need right in front of you.

As you embark on this journey everything will not be given. You will need to search and develop those methods. Gather your notes in an orderly fashion and as chaotic as a seems to stay organized understand that too is part of this process. 

`whoami` I’m ExecuteAtWill and I’m an Offensive Security Certified Professional. 

![](https://paper-attachments.dropbox.com/s_7075241856652EF31BB91F5A4E9433ABF28A4C020A8BFD9F936C74F79D6A3265_1601162473303_F_35_Pilot_Salute.gif)
