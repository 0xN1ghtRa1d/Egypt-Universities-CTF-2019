# Egypt-Universities-CTF-2019
Hey all this is 0xN1ghtRa1d , this is our writeups for Egypt-Universities-CTF-2019 .
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

So it's clear now he is just checking if the  argv[1] = 'cybertalent' which is the username and do the same thing for argv[2]='P@ss'.

# Flag:
flag{cybertalent:P@ss}


