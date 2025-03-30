# DigginDir - Forensics
Created by: carmengh  
Writeup by: Ethan Andrews (UofUsec)

## Description
So I tripped on an uneven sidewalk today.... and I dropped the flag somewhere (oops). It's gotta be here somewhere..... right?

## Writeup
### Initial Look
There appears to be a maze of files with random names. The challenge appears to be finding a specific file. We could do this manually, but we would rather take a more efficient approach.

### Solution
We can use the grep command to search for specific strings. We can use the recursive (-r) option to search through directories.

```
grep -r "wctf" .
```

This gives us the flag.

## Important Concepts
- recursive grep
