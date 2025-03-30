# REdata - Rev
Created by: Didkd  
Writeup by: Ethan Andrews (UofUsec)

## Description
An eZ RE challenge

## Writeup
### Easy Approach
For beginner challenges, there won't be much obfuscation. We can simply search for hardcoded strings in the file.
```bash
strings redata | grep "wctf"
```
This will return the flag.

### Structured Approach
If we want to approach this the same way we would approach a non-beginner challenge, we will decompile it with Ghidra to take a look at the source code.

The main function does not appear to have any method for obtaining the file.

![image](https://github.com/user-attachments/assets/319af5aa-4fd8-4a4e-b4a4-2cef18b244ff)

This must mean the flag is hidden somewhere in the data. We will take a look at the .rodata section (the section for read-only data).

![image](https://github.com/user-attachments/assets/9f42a821-ba72-4b1b-8d24-06256b21c9d4)

Here we can clearly see the flag.

## Important Concepts
- Ghidra
- strings command
- .rodata
