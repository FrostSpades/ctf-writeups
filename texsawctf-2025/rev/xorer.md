# xorer
Writeup by: Ethan Andrews (UtahSec)

## Description
I wonder what should be XORed with what...

## Writeup
### Initial Looks
The binary appears to query for a password.

![image](https://github.com/user-attachments/assets/1303cc39-c169-4600-bc48-0c021d71bab1)

### Code Analysis
We will analyze the binary using Ghidra.

We can see the main function query for the password.

![image](https://github.com/user-attachments/assets/50c3fc95-6067-4941-b2a1-6d2b79c041a4)

Then the check_password function verifies the password.

![image](https://github.com/user-attachments/assets/2950102f-149a-4b18-8a16-21903262890f)

The verification process appears to take each byte of the user's input, XOR's it with `0xa5` and then
checks it against a key. Because the XOR function cancels itself out, to determine the correct input,
we just take each value of the key, and then XOR it with `0xa5`.

![image](https://github.com/user-attachments/assets/aec4126f-1cfc-47ba-a6df-364b62478e36)

### Solution
We can write a python program that does this.

```python
bytes_list = [
    0xCB, 0x95, 0xD1, 0xFA, 
    0xD1, 0xCD, 0x96, 0xFA, 
    0xC3, 0xC9, 0x91, 0xC2
]

key = 0xA5

result = [chr(byte ^ key) for byte in bytes_list]
print(''.join(result))
```

Running this program, we get: `n0t_th3_fl4g`

When we input this into the program, we get the flag:

![image](https://github.com/user-attachments/assets/bb5fac0e-20ce-4d90-845d-c36f0974bf38)


## Important Concepts
- Ghidra
- XOR
