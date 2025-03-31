# Serialies
Writeup by: Ethan Andrews (UofUsec)

## Writeup
### Initial Looks
We are given a website link and the websites source code. Visiting the link, we get the following error:

![image](https://github.com/user-attachments/assets/346e2f18-c30c-4cbf-a7aa-eb737ef4ba67)

It appears that the website has not defined the default path `/`.

### Source Code Analysis
Looking through the various java source files, we see several classes that define data types. We notice that the PersonController.java
file is of interest.

![image](https://github.com/user-attachments/assets/f7df7b0d-0d81-4af7-9019-d03ada70369a)

It appears to define the path `/api/person`. When we travel to this path, we get:

![image](https://github.com/user-attachments/assets/e9f1a703-84e5-4582-9be7-07e0091aad73)

It appears to return a list of all the `person` objects. We can use the find function to search for the flag.

![image](https://github.com/user-attachments/assets/71d63d2e-a59c-4b6a-9fea-d7280ee70c8f)

Here we can see the flag.

## Important Concepts
- Java
- Website Paths
