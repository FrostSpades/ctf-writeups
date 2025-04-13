# Beginner Web
Writeup by: Ethan Andrews (UofUsec)

## Description
Hey, my son Timmy made his first website. He said he hid a 'secret' message within different parts of the website... can you find them all? I wanna make sure he isn't saying any swear words online.

The flag is broken up into 3 parts. The parts of the flag should be concatenated in the order they are numbered and then surrounded by the standard wrapper. For example: 'swampCTF{' + part1 + part2 + part3 + '}'

## Writeup
### Initial Looks
This appears to be a migraine inducing web server with a crazy moving graphic.

![image](https://github.com/user-attachments/assets/43b58041-99bb-4fd0-80cc-f6cb86fa15e3)

### Web Developer Tools
We start out by opening up the web developer tools. We are immediately greeted with the first part of the flag.

![image](https://github.com/user-attachments/assets/7c1654a9-963f-41d5-942b-82294f576131)

This gives us an insight. The insight is that each part of the flag is designated as "Part X of the flag:". This means we can search for other
parts using the find tool `ctrl + F` and searching for "flag".

We will now look through some of the other files. We notice there are two js files the server imports as scripts.

![image](https://github.com/user-attachments/assets/5f856b7b-0c80-48ce-850a-e4669ecdd76c)

Going to the first one and searching for flag doesn't lead to anything. Going to the second js file `main-34VY7I6V.js` and 
searching for flag gives us the following:

![image](https://github.com/user-attachments/assets/4eea9cef-0d83-4a1f-9eca-a787be482e96)

We appear to have found the flag parts 2 and 3. However, this javascript is very hard to read. We can use an online
js beautifier to better visualize how it works.

![image](https://github.com/user-attachments/assets/80e0a254-ad9c-425a-9cb4-5b774903228d)

## Javascript Analysis
After beautifying the code we can see how the flags parts are created. 

![image](https://github.com/user-attachments/assets/a48362d5-1f40-4994-96b6-2cf0cce607f5)

We can see that flag part 2 is created by AES decryption using r and n as arguments, and flag part 3 is created by
AES decryption using o and n as arguments. We can use the crypto-js library to recreate this code.

![image](https://github.com/user-attachments/assets/f8862bbb-7cff-4b12-ab73-d4aaf27d0e6d)

This prints out the flag parts:

![image](https://github.com/user-attachments/assets/28148bc6-47cf-443e-ad6f-fc5d2ebcd423)

Now that we have all 3 of the flag parts, we have the flag.

## Important Concepts
- HTML
- Javascript Beautifier
- AES Decryption
- Web Developer Tools
