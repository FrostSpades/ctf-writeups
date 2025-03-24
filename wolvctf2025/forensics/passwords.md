# Passwords
Created by: dree  
Writeup by: Ethan Andrews (UofUsec)

## Description
I heard you're a hacker. Can you help me get my passwords back?

## Writeup
### Initial Looks
In the zip file, we receive a .kdbx file. This file format is used by KeyPass, an open-source password manager.

Because of this, we can try to open it up in KeePass.
```
keepassxc Database.kdbx
```
However, it appears to require a password.

![image](https://github.com/user-attachments/assets/4695e502-bb0c-4290-b780-16f09fcbd59f)

### Solution

In order to crack the password, we must first obtain the password hash. Luckily, there is a utility provided
by john the ripper to extract the hash of the password.
```
keepass2john Database.kdbx
```

![image](https://github.com/user-attachments/assets/e0459399-181d-4661-9b5e-4511cadb6d0e)

We can then copy the actual hash (not the "Database:" part) to a file.

![image](https://github.com/user-attachments/assets/df740c83-1af5-4b32-b81d-4928684f6641)

Now that we have the hash, we can attempt to crack it using `hashcat`.

First, we need to find the setting for KeePass. `hashcat --help` lists all the hash modes, and we can 
grep the desired mode.

```
hashcat --help | grep "KeePass"
```

We see that the mode for KeePass is 13400.

![image](https://github.com/user-attachments/assets/116d7134-d39c-41e0-8926-1541e0952c50)

Now we can try to crack the hash. We will use the `rockyou.txt` wordlist.

```
hashcat -m 13400 pass.txt /path/to/rockyou.txt --show
```

We can see that the password is `goblue1`.

![image](https://github.com/user-attachments/assets/b5bc1920-133e-4af4-bc71-85a788591c98)

Now that we know the password, we can open up the file in KeePass

```
keepassxc Database.kdbx
```

There are many passwords saved. We find the flag in the home banking password.

![image](https://github.com/user-attachments/assets/67fef9d9-2063-4457-a4f3-6784a50c5f17)


## Important Concepts
- KeePass
- john the ripper
- hashcat
