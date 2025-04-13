# Too Early 4 Me
Writeup by: Ethan Andrews

## Description
Ever since I got back from spring break, the semester's been getting pretty rough. 
I have an 8am class, and a commute - I'm waking up way too early for me! So, I wrote 
a program to survey everybody to see how THEY feel when their alarm clock goes off 
that early. We'll see...

## Writeup
### Initial Looks
When we run the program, it appears to be a yes or no survey.

![image](https://github.com/user-attachments/assets/9a138e26-69f4-42ee-a847-e0b7fbd5ab70)

### Code Analysis
We can analyze the code using Ghidra.

The main function appears to register a signal alarm handler function.

![image](https://github.com/user-attachments/assets/70104180-7eda-4729-8e02-a9ba07093de7)

Going to that function, we can see the `decode_flag()` function call.

![image](https://github.com/user-attachments/assets/e5b2c9cf-ce3b-45d6-96ca-bb7a38be8543)

### GDB

We can try simply calling this function from within gdb.

```bash
gdb ./chal
```


```bash
break main
```


```bash
run
```


```bash
jump sigalrm_handler
```

Then we can see the flag getting printed:

![image](https://github.com/user-attachments/assets/1d48abf4-8149-40af-a7d9-938955b312aa)

## Important Concepts
- GDB

