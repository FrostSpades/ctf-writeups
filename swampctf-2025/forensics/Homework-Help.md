# Homework Help
Writeup By: Ethan Andrews (UofUsec)

## Description
I accidently lost some of my class notes! Can you help me recover it? (Note: Unzipped size is 4GB)

## Writeup
### Initial Looks
We are given a zip file. Inside the zip file appears to be an `image.vhd` file. We can look through this using 7zip
(on Windows) as a basic analysis.

![image](https://github.com/user-attachments/assets/19fe252a-4fde-4097-8559-cdf56a8ae3a2)

We see several directories. According to the description, it looks like we need to look for class notes.
Inside the school directory, we see several subjects:

![image](https://github.com/user-attachments/assets/b113aae9-41ff-4f56-84f8-a6c0366c20d9)

Noticably, the `Hacking` directory is empty.

We can use 7zip to extract these files. We can try to search for certain files, or 
grep the flag structure, but nothing appears to work.

### File Recovery
By looking at the description, it hints that we need to "recover" their notes. This hints that we will need to
recover deleted files.

There are several tools we can use for this. I will be using the free version of `ReclaiMe` due to its simplicity,
but it is recommended to use other free open-source tools because these give you greater functionality.

Opening the file in ReclaiMe, we can see that a file named `Hacking Notes.docx` was recovered.

![image](https://github.com/user-attachments/assets/b487b568-f2e3-4839-b38b-51b8c08cec68)

Inside of this file, we can clearly see the flag.

![image](https://github.com/user-attachments/assets/592aba50-670e-4a34-b4df-afa7552927cf)


## Important Concepts
- 7zip
- Deleted File Recovery
- ReclaiMe
