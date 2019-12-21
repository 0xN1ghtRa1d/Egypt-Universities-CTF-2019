# Egypt-Universities-CTF-2019
Hey all this is 0xN1ghtRa1d , this is our writeups for Egypt-Universities-CTF-2019 .
# Challenge name
Login
# Category
Malware Reverse Engineering
# Level
Easy
# Points
50
# Description
You are given an ELF file which require two paramters,first one is the username and second one is the password.
![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/first.png)
So it's time for IDA.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/idaview.png)

So it's clear now he is just checking if the  argv[1] = 'cybertalent' which is the username and do the same thing for argv[2]='P@ss' which is the pass.

# Flag
flag{cybertalent:P@ss}
# Challenge name
Pekz
# Category
Digital Forensics
# Level
Easy
# Points
50
# Description
You are given a pcap file which contain some HTTP requests and some TCP stream, you can find the flag easily just by viewing the file strings.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/pekz.png)

# Flag
FLAG{0h_dump_is_ez_recover_is_eazi3r!!}
# Challenge name
Keep Calm 
# Category
Digital Forensics
# Level
Easy
# Points
100
# Description
In this challenge we are give gif which contain some random chars.
![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/scatter.gif)
