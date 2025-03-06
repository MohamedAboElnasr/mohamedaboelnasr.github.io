---
title: Vulnnet Roasted
date: 2025-02-11 23:33:37 +0200
categories: [Active Directory]
tags: [AD]
media_subpath: /assets/images/vulnnet
---
# Introduction
 I would like to write a write-up about a machine I solved on TryHackMe called Vulnnet:Roasted, which is an Active Directory machine. My focus will not be on how I solved the machine, but rather on explaining the tools and techniques I used to solve it. Before I start, I would like to say that this is my first write-up, so please forgive any mistakes and I hope someone benefits from this post \^_\^

---

## List of Tools Used and Their Purposes
1. Nmap
2. Smbclient
3. Crackmapexec
4. lookupsid
5. GetNPUsers
6. Hashcat
7. GetUserSPNs
8. evil-winrm
9. secretsdump

---

## List of Techniques Used for Compromising the Machine and Escalating Privileges
1. RID brute force attack
2. ASREPRoasting
3. Kerberoasting
4. Escalating privileges using administrator's password hash
---
The first thing I did was use `Nmap` to scan and identify the open ports and services running. As it turned out, I found that the SMB port was running along with Kerberos and LDAP, and there was a domain named `Vulnnet-rst.local` as shown in the images.
![](nmap.jpg)

Next, I started enumerating the SMB service using `smbclient`. I found that anonymous login was allowed, but with limited permissions on two folders containing text files. I downloaded these files but didn’t find anything useful in them.
![](smbclient.jpg)  
The second thing I thought of doing was brute forcing the User RIDs to gather the users present on the domain. The RID (Relative Identifier) is part of the SID (Security Identifier), which is a unique identifier assigned to each user, group, or computer account in a Windows domain. The SID uniquely identifies the account, while the RID is the last part of the SID that specifically identifies an account within a domain.

I used `crackmapexec` with the following command to do this:
```bash
crackmapexec smb -u anonymous -p '' ip --rid-brute
```
![](Crackmapexec.jpg)
The third step was to list the users present on the domain, which I extracted using `crackmapexec`. From the Nmap scan, we saw that the Kerberos port was open. This led me to start enumerating the users I had gathered to see if any had the "Does not require Pre-Authentication" feature enabled. This would allow me to get the hash of that user's password and crack it. The process is as follows:

1. Send a request to the KDC (Key Distribution Center) to get a TGT (Ticket Granting Ticket).
2. The KDC responds with a valid TGT because the "Does not require Pre-Authentication" feature is enabled for that user.
3. Capture the TGT, which contains the password encrypted.

All of this can be done using the `GetNPUsers` tool, which is part of the Impacket suite. Here is the command I used:
```bash
' GetNPUsers domain_name/ -dc-ip ip -usersfile file_name -no-pass -request'
```
![](GetNPUusers.jpg)  
The tool will then perform all the steps mentioned above, and we will find that there is a user without Pre-Authentication enabled named `t-skid`. This will yield the user's password hash. Next, we will crack this hash using `hashcat`.
![](hashcat.jpg)
This is essentially an ASREPRoasting attack.


Now we have a username and password. I tried to log in with `evil-winrm`, but this user did not have sufficient privileges. I then used this user to check which Service Principal Names (SPNs) were set, and from there, I could get the password hash. SPNs are used in Kerberos authentication and are names linked to a user, allowing that user to access certain resources on behalf of the service with its privileges.

Here comes the Kerberoasting attack, which proceeds as follows:
1. Send a request to the KDC (Key Distribution Center) to get a TGT (Ticket Granting Ticket) to communicate with the service that has an SPN.
2. The KDC responds with a TGT response containing a session key, which can be used to encrypt any subsequent communication.
3. Send another request, this time a TGS-REQ (Ticket Granting Service Request).
4. The KDC responds with the service ticket encrypted, which includes the service's password hash.
All of this will be done using `GetUserSPNs`, which is also part of the Impacket tools, using the following command:
```bash
GetUserSPNs domain_name/username@ip:'password' -dc-ip ip -request
```
 ![](GETSPN.jpg)
 5. Crack this password hash using `hashcat`.
 ![](hashcat_enterprise.jpg)
Then, my friend, I finally managed to log in to the machine using `evil-winrm` and was able to obtain the first flag. We still have one more step to go, so please bear with me.
![](fla1.jpg)
Earlier, when I mentioned that there were folders available when we performed enumeration on SMB but we couldn't access them due to insufficient permissions, we will try again, but this time with the username and password obtained from `GetUserSPNs`. 
![](smbclient2.jpg)
I did that, and after trying several folders, I found a file named `Resetpassword.vbs` inside one of the folders in `NETLOGON`. I downloaded this file and found user credentials within it, which, by the way, belonged to a member of the administrators group.
![](vbsscript.jpg)
I took the user and their password and decided to perform a hash dump of the SAM file. This is done using the tool mentioned earlier, `secretsdump`, which is also part of the Impacket suite. Using this, I obtained the NTLM hash and logged into the machine using just the hash. This allowed us to retrieve the second and final flag.
![](secretsdump.jpg)
![](evil-winrm.jpg)
And that's it, my friend. If you’ve reached this point, I thank you for your time, and I hope you found it useful.
