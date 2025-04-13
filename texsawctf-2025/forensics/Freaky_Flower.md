# Freaky Flower
Writeup by: Ethan Andrews

## Description
I'm sorry about the other flower challenge! I hope this one makes up for it!

Flag format: texsaw{hidden_word}

## Writeup
### Initial Looks
We are given a .psd file of a flower.

![image](https://github.com/user-attachments/assets/c049858d-73e5-4fa6-88ce-e9f1b1124c1b)

According to the challenge description, we are searching for a hidden word.

### File Metadata
We can look at the file metadata using exiftool.

```bash
exiftool chal2.psd
```

![image](https://github.com/user-attachments/assets/4c917729-2fb1-4498-820c-bfaca46ad62f)

We can see the hidden string in the `Layer Names` field: `sneaky_sunflowers_sure_suck`.

## Important Concepts
- exiftoool
