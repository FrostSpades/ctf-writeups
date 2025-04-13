# Planetary Storage
Writeup By: Ethan Andrews

## Description
My friend found this strange file while perusing his computer, but we can't read it. Can you figure out what it is and get the information from it?

Difficulty: Easy/Medium

The flag is in the standard format.

## Writeup
### Initial Looks
Inside of the challenge directory, we see many files. In particular, we see `.ldb` files. After some quick research, we see that
these can be interpreted as database files.

If we `cat` these files, we can see that they contain some remnants of dictionary data.

![image](https://github.com/user-attachments/assets/49c8a644-7562-43ee-aa73-81464c89b45d)

We noticeably see a payload key in 000002.ldb that contains a value that appears to be base64 encoded.

```
eyJrZXkiOiJcIjdiZjFjNTRlLTA5MjAtNGU2Zi1iNTBiLTE0ZDgzODY3NDdmN1wiIiwib3AiOiJQVVQiLCJ2YWx1ZSI6ImV5SmtZWFJoSWpwYklsUm9hWE1pTENKcGN5SXNJbUVpTENKeVpXUWlMQ0pvWlhKeWFXNW5JU0pkTENKcFpDSTZJbHdpTjJKbU1XTTFOR1V0TURreU1DMDBaVFptTFdJMU1HSXRNVFJrT0RNNE5qYzBOMlkzWENJaWZRPT0ifQ==
```

After decoding it, we obtain the following:
```
{"key":"\"7bf1c54e-0920-4e6f-b50b-14d8386747f7\"","op":"PUT","value":"eyJkYXRhIjpbIlRoaXMiLCJpcyIsImEiLCJyZWQiLCJoZXJyaW5nISJdLCJpZCI6IlwiN2JmMWM1NGUtMDkyMC00ZTZmLWI1MGItMTRkODM4Njc0N2Y3XCIifQ=="}
```

We get another dictionary, with another key "value" with a value that again appears to be base64 decoded:
```
eyJkYXRhIjpbIlRoaXMiLCJpcyIsImEiLCJyZWQiLCJoZXJyaW5nISJdLCJpZCI6IlwiN2JmMWM1NGUtMDkyMC00ZTZmLWI1MGItMTRkODM4Njc0N2Y3XCIifQ==
```

Decoding this, we can see that this did not lead anywhere.
```
{"data":["This","is","a","red","herring!"],"id":"\"7bf1c54e-0920-4e6f-b50b-14d8386747f7\""}
```

### Base64 Decode
We see that there are several other candidates for base64 decoding. Using an online decoder `https://www.base64decode.org/` 
we can decode the entire file at once by simply extracting the data with `cat` and copy/pasting it into the website.

![image](https://github.com/user-attachments/assets/467efe26-066b-4042-8498-e949200afa99)

Because we saw that the previous example required many instances of decoding, we will decode it again.

![image](https://github.com/user-attachments/assets/a01cf361-34a7-4811-b140-d890c80cc5db)

In the value section, we clearly see something of interest. We see the partial flag:

![image](https://github.com/user-attachments/assets/ffde8315-c454-4588-99f3-bf3dab57329d)

Luckily, only the beginning part of the flag was missing. This gives us the flag

```
swampCTF{1pf5-b453d-d474b453}
```

## Important Concepts
- Base64
