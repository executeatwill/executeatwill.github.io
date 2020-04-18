Local File Inclusion vulnerabilieis entail when a user inputs contains a file path which results in retrieval of unintended system files via a web service.

----------

Legal Usage: The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “ethical hacker” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.
By continued reading, you acknowledge the aforementioned user risks/responsibilities.

----------

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587229250885_image.png)


# Access Web Server

connect to `http://10.10.246.197`


![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587229425182_image.png)


## Accessing LFI point

Within URL input fields request containing `?file=` can optionally be used to read arbitrary files within the system. To which private files such as passwords, ssh keys along side an array of data can be retrieved by an attacker.

Navigating the page, after click the “Leave a Review” button yeilded a field in the address bar og `/home?page=about`

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587229688478_image.png)


## Testing LFI Point

At this point utilzing a request such as `../../../../etc/passwd` testing if request is returned:

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587229784929_image.png)


To which at the bottom of the page yielded the `/etc/passwd` file. From the information gathered from the “passwd” file we can find a user name “Falcon”


## Retrieveing falcon .bashrc 

The `.bashrc` file contains imporatin inforatmin in regards to the shell of the user falcon. Calling the file from the LFI to enumerate falcon users shell:

    http://10.10.246.197/home?page=../../../../home/falcon/.bashrc

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587230079961_image.png)


## Capturing falcons ssh key

Using the LFI the `id_rsa` of the user can be returned from the `/home/falcon/.ssh/id_rsa` directory

Switched over to burp to capture the request of the `id_rsa`

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587230417165_image.png)


save the contents of the id_rsa to a file: `Falcon_id_rsa`

Change the chmod to 600 and access ssh as falcon:

    chmod 600 falcon_id_rsa
    ssh -i falcon_id_rsa falcon@10.10.10.246.197

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587230855110_image.png)


## Escalate from falcon to root

Check if user falcon has any sudo abilities:

    sudo -l

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587231014312_image.png)


GTFObins for `journalctl` - states to launch the binary and type `!/bin/sh`

Link: [https://gtfobins.github.io/gtfobins/journalctl/]()

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587231265780_image.png)

![](https://paper-attachments.dropbox.com/s_F26A4BFA3DC81F5BA21AC048F1DFCB30AA82E2F5DD08A757544AC97D4892C68F_1587231081551_image.png)
