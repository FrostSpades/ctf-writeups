# Eval is Evil
Created by: EmptyBytes  
Writeup by: Ethan Andrews (UofUsec)

## Description
If eval is so bad, then why is it so easy to use?

## Writeup
### Initial Analysis
We are given a python file, and it appears to just run eval on user input and checks to see if it is equal to a random
integer, which then prints a flag.

![image](https://github.com/user-attachments/assets/ddd018c5-75e2-4578-ab79-51d20bfa7d9b)

### General Information
`eval()` is a very dangerous function that evaluates ANY expression in python.

For example:
```python
x = eval("2 + 4")
# Sets x = 6
```

You can also print things out:
```python
eval("print(32)")
# Prints out 32
```

### Solution
One might think the correct solution is to try and set `guess` equal to `correct` to make the code print out the flag. However, eval is 
executed before correct is assigned, so we know this is a red herring.

Luckily, the solution is much simpler. We can actually just print out the flag directly from within the eval function.
This can be done with the following input:

```python
print(open('flag.txt').read())
```

Feeding this in successfully prints the flag.

![image](https://github.com/user-attachments/assets/ab736aa5-ad86-483d-817c-299d78295c10)

## Important Concepts
- NEVER EVER USE EVAL!!!
