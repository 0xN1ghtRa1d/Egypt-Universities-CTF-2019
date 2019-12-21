# Egypt-Universities-CTF-2019
Hey all this is 0xN1ghtRa1d team , this is our writeups for Egypt-Universities-CTF-2019 .
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
In this challenge we are given gif which contain some random chars.
![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/scatter.gif)

So now the first thing we have to do here is extracting the gif frames.
I used this website https://picasion.com/get-frames/ to extract all the frames, after extraction we will find that each frame contain a 3 or 4 chars.
Now we have these chars ['zg5','MTI','U2N',,'MAo=','zND'] after looking to these chars it seems like it's a base64 string but the string
isn't in the right order after some trys i found that we have to generate all possible permutations of the strings and we know that the last part of the flag is 'MAo='.

So i wrote this simple script :D

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/script1.png)

After runing the script we found two valid strings.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/script_result.png)
# Flag
flag{1234567890}
