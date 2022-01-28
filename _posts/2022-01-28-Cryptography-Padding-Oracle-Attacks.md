---
published: false
---
Stepping through understanding padding on block cipher algorithms AES, 3DES in Electronic Code Block (ECB and Cipher Block Chaining (CBC) modes. Decryption of session cookie is of a vulnerable webapps via Oracle Attack.

----------

Legal Notice && Usage: *The information provided by executeatwill is to be used for educational purposes only. The website creator and/or editor is in no way responsible for any misuse of the information provided. All the information on this website is meant to help the reader develop penetration testing and vulnerability aptitude to prevent attacks discussed. In no way should you use the information to cause any kind of damage directly or indirectly. Information provided by this website is to be regarded from an “*[*ethical hacker*](https://www.dictionary.com/browse/ethical-hacker)*” standpoint. Only preform testing on systems you OWN and/or have expressed written permission. Use information at your own risk.* *By continuing, you acknowledge the aforementioned user risk/responsibilities.*

----------

# Understanding Padding

Padding is adding data in series to either the beginning middle or end of a message prior to encryption.

in cryptography block cipher algorithms such as AES, 3DES in electronic code block and cipher block chaining mode requires that input be the exact same block size on adjacent sides.  Thus is a plaintext is not the same size of the block the extra data used is referred to as the padding which is before the encryption.

when an application attempts to decrypt a cipher text it must know how to remove the padding.

the cons of these two modes:

- CBC mode can leak the information if handed poorly
- ECB mode can leak the same cipher text block

**Two Types of Padding Standards**

Public Key Cryptography Standards
PKCS #7 - current used standard - allows block sizes up to 255
PKCS #5 -  prior standard only applicable for 8 byte blocks

Note: Padding will be composed of the same number as equals the number the bytes required


## Example  1

Encrypting “Iamplaintext” plaintext with DES encryption in ECB mode 

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643401284822_image.png)


Encryption of DES the block size is 64bits
Blocks broke into equal 8 blocks
there are 4 empty blocks delineated by the “?” in the second block


## Example 2

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643401881448_image.png)


As the padding is added via the PKCS #7 where where bytes are missing they are replaced the the byte number.

“0x01” (one byte missing and padding added)
“0x02” (two byes missing and padding added)
“0x03” (three bytes were missing and padding added)

During the decryption process the application first decrypts the data then the padding. As the padding is sequenced by changing padding can cause an attack can depict the encrypted data by providing plaintext.


# Padding Oracle Attack


![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643402315814_image.png)


AES encryption is broken into 16bit block sizes

an attacker can create an oracle using `? = 0x01 ^ X` which returns as valid via XOR.

Since the last byte can have up to 256 values an attacker can manipulate the `n - y` block until all the possibilities have occurred or when padding written is valid (using x02, x03… etc)

By using pass field response the value can guessed and later the data can be decrypted.


## Detecting Vulnerable Service

Can be accomplished by inspecting the following attributes:


- cookies - (logging into a service and evaluating cookie - value/length of cookie is the same)
- request parameters - (can look like random values or ciphertext, remove one or more characters and analyze the response)
- Hidden field values

In these instances the application could have a padding oracle if an error is thrown when manipulating the value sizes. Further more cookie values can be inspected against base64 if the output looks random and the length is a multiple of a common block cipher size can identify a padding oracle.


# Demonstration

Web application running that displays a username when the cookie length is not sufficient. 

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403273848_image.png)



Decrypting the data to gain administrator access by create a user `xxxx` and password

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403419104_image.png)


cookie created with the name `PadOrc`

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403462908_image.png)


Inspect the cookie length 

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403569103_image.png)


by removing a character from the sequence and replacing with cookie on webpage the server throws an error:

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403708006_image.png)




## Padbuster

Automated script for performing Padding Oracle Attacks
Github: https://github.com/AonCyberLabs/PadBuster

syntax:

    padbuster http://10.0.2.4/padding0/index.php "gNA.......2BJ" 8  -cookie "padOrc=gNA.......2BJ" -error "Padding is altered"

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643403998226_image.png)


Completed attack:

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404035465_image.png)


**Admin user cookie** 
as we have the admin user name we can pass the flag “plaintext” and attain an admin cookie.

syntax:

    padbuster http://10.0.2.4/padding0/index.php "gNA.......2BJ" 8  -cookie "padOrc=gNA.......2BJ" -error "Padding is altered" -plaintext "user=prodigiosMind"

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404209076_image.png)


Completed attack:

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404245930_image.png)


ciphertext of administrator account cookie discovered.

Pass as cookie on browser:

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404288674_image.png)


Page refreshed:

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404307878_image.png)

![](https://paper-attachments.dropbox.com/s_6DDAF448B538453129C7A542DEA81938EEA105A8AB739E29584AAB7FF8CD8BB5_1643404341357_image.png)

video source reference: https://www.youtube.com/watch?v=ilBFiecaO4I

