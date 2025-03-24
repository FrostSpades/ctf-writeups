# PicturePerfect - Forensics
Created by: carmengh  
Writeup by: Ethan Andrews (UofUsec)

## Description
Wow what a respectful, happy looking lad! Hmmmmmmm, all I see is a snowman... maybe some details from the image file itself will lead us to the flag.

## Writeup
### Initial Looks
It appears to be a plain image. The description hints at looking at the metadata.

### Solution
To look at the metadata of an image, we can use the exiftool.
```
exiftool hi_snowman.jpg
```

We can see the flag hidden in the title section.

![image](https://github.com/user-attachments/assets/f03d9e2e-1234-4f7b-bf86-32b197fa1414)

## Important Concepts
- Exiftool
