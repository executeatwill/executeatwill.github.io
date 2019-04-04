---
published: false
---
April 4th, 2019, With high anticipation from the cybersecurity community the NSA release the open source of its Software Reverse Engineering (SRE) framework Ghidra. This all gaining traction as the organization reaches out to garner potential new employees. While the effort seem to be an interesting avenue to pursue the infosec community welcomes the open-sourcing of such powerful tools.



![source: https://twitter.com/NSAGov/status/1113788370461843461](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554413860789_image.png)




# Installation

Over the next few steps we will install Ghidra on Kali. 

Official Installation guide link: https://ghidra-sre.org/InstallationGuide.html

## Download:

Ghidra Download page: https://www.ghidra-sre.org/
Github Repository Link: https://github.com/NationalSecurityAgency/ghidra


## Requirements:

Hardware:

- 4 GB RAM
- 1 GB Storage
- Dual Monitors 

Software:

- Java 11 Runtime & Development Kit(JDK) - OpenJDK recommended
  *installation instructions included within this tutorial.*


1. Head to the Ghidra download page and click “Download Ghidra v9.0.2”


![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554416170915_image.png)


Unzip

    unzip ghidra_*_PUBLIC_*.zip

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554416361404_image.png)



2. Install OpenJDK required dependencies
    apt-get install default-jdk

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554416677632_image.png)



# Launching Ghidra

in directory uncompressed:

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554416824548_image.png)


launch ghidra

    ./ghidraRun

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554416903325_image.png)


From this point you can load up a binary or application and move through the compiled code to proceed reverse engineering.

For more information on how this application can be leverage check out this great Youtube video from TechChip
Link: https://www.youtube.com/watch?v=GuZLAsRNpuI


## Ghidra Cheat sheet:

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554417072553_image.png)

![](https://paper-attachments.dropbox.com/s_00E9ABB011398466C10F5E4DF87608A33B1E7F87240EFA3C684D0E4B7CBE3AE2_1554417182362_image.png)


