# Deprecated Site
Writeup by: Ethan Andrews

## Description
CSG's left an old webpage up on accident. It's old and deprecated, maybe you should do us a favor and get rid of it?

## Writeup
### Initial Looks
We are greeted with a website, and there do not appear to be any ways to directly interact with the website via input
fields or buttons.

![image](https://github.com/user-attachments/assets/b4e7d959-1631-45a1-8c62-4e86316cc843)

It also has a message indicating that the webpage should be deleted.

### Exploring
Since we don't have much to work off of, we can take a look at the `/robots.txt` file.

![image](https://github.com/user-attachments/assets/749517eb-4825-4ef9-ac0e-d5161816d971)

We can see that there's a path labeled `/flaghint.txt`. Visiting this path, we see the following message:

![image](https://github.com/user-attachments/assets/37ed61ee-9b43-4701-a64d-1e3fd72441ed)

So this hint indicates that we need to "delete" the flag. This hints that maybe we should
send a DELETE request to the server.

### Burp Suite

We can construct a DELETE packet using Burp Suite by simply capturing a GET request and changing the GET to DELETE:

![image](https://github.com/user-attachments/assets/e078befe-89a7-4d68-a387-709098ae1ec9)

This returns the flag:

![image](https://github.com/user-attachments/assets/29fec047-bbfa-4eb3-91db-69f6b410991a)

## Important Concepts
- Burp Suite
- Delete Requests
