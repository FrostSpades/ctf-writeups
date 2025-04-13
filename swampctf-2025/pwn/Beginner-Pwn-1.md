# Beginner Pwn 1
Writeup by: Ethan Andrews (UofUsec)

## Description
Are you really admin?

This challenge serves as an introduction to pwn that new ctfers can use to grasp basic pwn concepts.

## Writeup
### Initial Looks
By executing the provided file, we can see that this serves as a tool for teaching buffer overflow.

![image](https://github.com/user-attachments/assets/f153ee17-70cb-4cf3-bfeb-ddd35e6f2ff4)

### Code Analysis
By analyzing the source code, we can see that it queries for user input and then checks to see if the user is_admin. We can also see that 
it is vulnerable to buffer overflow. When it reads in the name, any characters entered after 10 characters will overflow into is_admin.

![image](https://github.com/user-attachments/assets/3cbb5979-7c47-459f-8631-0530aab8d83b)

Because C code treats any non-zero value as True in a boolean, simply overflowing into is_admin will give admin access.

### Exploit
This means we can simply input 11 characters. Then we can choose 'y' and print the flag.

![image](https://github.com/user-attachments/assets/fedb7b50-fca6-4b87-8ae3-343033ef524a)

## Important Concepts
- Buffer Overflow
