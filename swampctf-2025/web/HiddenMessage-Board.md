# Hidden Message-Board
Writeup by: Ethan Andrews (UofUsec)

## Description
Somewhere on this message-board is a hidden flag. Nothing has worked so far but we have noticed a weird comment in the HTML. Maybe it's a clue?

## Writeup
## Initial Looks
This appears to be a messaging application. You can see users' messages and can post your own messages.

![image](https://github.com/user-attachments/assets/e890e7b3-61a8-4399-b6f7-c664783b252d)

The challenge description states that we are supposed to find something important in the html code.

## Developer Tools Analysis
Opening the developer tools, we can now search for important content.

![image](https://github.com/user-attachments/assets/7e9368d5-b0b7-497a-a2d1-190c80ac097c)

In one section of the code, we appear to have found the important part. It states that they need to have removed flagstuff
with a specific code. We can see the flagstuff item directly above this comment. This html element also has a code field.
Since we are given the code field, we can insert the code into the code field.

![image](https://github.com/user-attachments/assets/e7ba1167-38f4-4e3f-8d0d-929102fa4b9f)

However, this does not appear to have done anything.

### Javascript analysis
We can analyze the javascript for more functionality to determine how this works. There appears to be a Messages.tsx file
where we see the getFlag() function being defined.

![image](https://github.com/user-attachments/assets/005ad9e1-9643-40ea-a03a-31fd5998b08f)

Inside of the App.js file, we can see this function being imported.

![image](https://github.com/user-attachments/assets/adcb350c-d7b6-47a9-be31-22acfa420abb)

Upon further analysis, we see where the flag gets printed.

![image](https://github.com/user-attachments/assets/0afe63a8-bbef-4206-9f3b-91d7ac942349)

It checks for the correct code whenever App() is called. Because this is a React component, we know that App() gets called
whenever any of the elements is updated. This means now we can simply update the text box.

![image](https://github.com/user-attachments/assets/ed49ecef-eb4e-4b37-b765-fa8ae1c9abe9)

This gives us the flag.

## Important Concepts
- Developer Tools
- React.js
- HTML
