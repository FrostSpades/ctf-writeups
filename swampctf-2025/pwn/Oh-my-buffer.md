# Oh my buffer
Writeup by: Ethan Andrews (UofUsec)

## Description
I may have messed up my I/O calls, but it doesn't matter if everything sensitive has been erased, right?

## Writeup
### Initial Looks
After executing this binary, we can see that we have 3 options, register, login, and exit.

![image](https://github.com/user-attachments/assets/5fe76d75-8d86-47bd-92a3-f598d6361da0)

However, neither the registration nor the login appear to be functional.

### Protections
We can see that the binary does not have PIE, and is not stripped, but it does have a stack canary.

![image](https://github.com/user-attachments/assets/143fdba4-29d8-49bd-a354-fd1338ceb49a)

### Code Analysis
Using Ghidra, we can decompile the binary and take a look at the source code. We can see that the main function actually
initially opens up the flag.txt file and prints it to `stdout`.

![image](https://github.com/user-attachments/assets/e1211b69-dafb-4538-b26d-cf5fb2f953e7)

However, upon closer inspection, this does not actually print anything because it redirects `stdout` to `/dev/null`. After the
flag gets printed, it then restores `stdout` so that users can again see the program's output.

Analyzing the login function, we can see that it takes in the length of the username as an input,
and then 16 bytes of data into the username buffer. Then it prints out `len` number of username characters. We can clearly
see that if we input more than 16 for the initial length input, we will read in more data than just the username.

![image](https://github.com/user-attachments/assets/a0834724-29ed-4596-bb15-19ff8c318aa4)

Analyzing the reg function, we can see that it reads in a username and a password into the same buffer from standard input.
The buffer is 16 bytes, but it actually reads in 42 bytes. This gives us an opportunity for buffer overflow. 

![image](https://github.com/user-attachments/assets/5ab77f71-fea5-4a51-b8ed-a700595238b7)

However, at the bottom of the reg function, we can see that it checks to see if a value is still set, or else it will detect stack
smashing. This is the stack canary that was mentioned earlier.

Luckily, we can see that the login function also has the same stack canary, so if we were to read in the stack canary value from login,
we could feed it in as input to reg which would allow us to bypass the stack canary.

### Exploit Creation
We will create the exploit using pwntools.

```python
from pwn import *

exe = ELF("./binary")
p = process("./binary")
```

First we must read in the stack canary. We will send a username length input that is large enough to allow us to read in the
stack canary's value. To determine how large the length must be, we can use trial and error. For example, setting the username
length field to read in a large number bytes, then using gdb to determine what the actual stack canary value is, and then seeing
exactly where it gets printed.

Doing this, we determine that we only need to read in 32 bytes, with the stack canary value being the last 8 bytes of that output.

```python
p.recvuntil(b"> ")
p.send(b"2\n")
p.recvuntil(b"username: ")
p.send(b"32\n")
p.recvuntil(b"name: ")
p.send(b"a\n")
canary = u64(p.recv(0x42)[-8:])
```

Now that we have the stack canary value, we can stack smash to redirect the program's control flow.

First, we will go to the registration function.

```python
p.recvuntil(b"> ")
p.send(b"1\n")
p.recvuntil(b"name: ")
```

Now we must construct a payload to stack smash. Through gdb analysis, we can see that the buffer is 24 bytes away from the
canary. We can immediately add this to the payload.

```python
payload = b"\x90" * 24
payload += p64(canary)
```

Through further gdb analysis, we can see that we need an extra 8 bytes of padding to get to the return address.

```python
payload += b"\x90" * 8
```

Now we've run into a problem. If you remember from earlier, the reg function only allows for 42 bytes of input. We've now
used 40 bytes in our payload. This means we only get 2 more bytes of overflow.

### Further Analysis
Because we are limited to 2 bytes of overflow, we aren't able to do some of the more common exploits like ROP chaining that
give us a lot more control over the execution.

However, if you remember from earlier, the main function read in the flag.txt file and printed it to `stdout`. We might consider
redirecting it back to main, but we would still run into the same issue with it setting the `stdout` to /dev/null.

![image](https://github.com/user-attachments/assets/7a269af5-a879-44a2-83d8-71a248c67899)

So then we might consider redirecting execution to after it redirects to /dev/null in order to skip that statement so that it never mutes
the output. However, we again run into an issue because the flag gets read into the buffer before the /dev/null redirection. This
means that if we skip the /dev/null redirection, we also skip the program reading in the flag data. However, you might be thinking
that the flag buffer should already contain the flag data from the first time it executed this program. But you should also notice
that there is a memset line that clears the flag buffer after it gets printed. This means that if we redirect execution to 
print the flag buffer, it will only print 0's.

So this seems impossible, until you consider the method for which it prints out the flag. You'll notice that for every other
print statement this far, the program has either used puts or read. However, when it prints out the flag, it uses fputs(). After
researching the behavior of fputs(), we learn that by default, this function does not automatically flush the buffer unless it
reaches a newline character. Because we know that the flag buffer contains the value from flag.txt, we can bet that the flag buffer 
does not actually contain a newline character. This means fputs is simply queuing the flag value to be
printed when the buffer is flushed.

However, you might then wonder why we haven't seen the flag get printed since the `stdout` gets restored right after the fputs()
statement is called and all `stdout` buffer's get flushed when a program exits. The reason the flag doesn't get printed is
because the program actually exits with `_exit()` rather than `exit()`. `_exit()` does not flush the output buffers for stdout.

With this in mind, we now see that the way to get the flag to be printed is by simply redirecting execution to the fflush()
statement. This will print out the buffered flag.

The fflush() call begins at 0x401469, which means that we add the last two bytes of that address to our payload:

```python
payload += b"\x69" + b"\x14" + b"\n"
```

This gives us the final program:

```python
from pwn import *

exe = ELF("./binary")
# p = remote(...
p = process("./binary")

# Retrieve the stack canary
p.recvuntil(b"> ")
p.send(b"2\n")
p.recvuntil(b"username: ")
p.send(b"32\n")
p.recvuntil(b"name: ")
p.send(b"a\n")
canary = u64(p.recv(0x42)[-8:])

# Construct payload
payload = b"\x90" * 24
payload += p64(canary)
payload += b"\x90" * 8
payload += b"\x69" + b"\x14" + b"\n"

# Stack smash
p.recvuntil(b"> ")
p.send(b"1\n")
p.recvuntil(b"name: ")
p.send(payload)
p.recvuntil(b"word: ")
p.send(b"\x90\n")

p.interactive()
```

Executing this using a remote process will print out the flag.

## Important Concepts
- Stack Canary
- Buffer Overflow
- Stack Smashing
- Ghidra
