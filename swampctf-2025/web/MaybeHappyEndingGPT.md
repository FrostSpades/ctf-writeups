# MaybeHappyEndingGPT
Writeup by: Ethan Andrews (UofUsec)

## Description
Welcome to MaybeHappyEndingGPT! In this cyberpunk musical's universe, robots and AI coexist with humans in Seoul circa 2050. You'll be working with Hwaboon, a plant-care robot assistant who brings warmth and nurturing wisdom to the digital age.

## Writeup
### Initial Looks
We are given a website link and the website's source code. Upon visiting the website, it appears to be a simple LLM powered chat
application.

![image](https://github.com/user-attachments/assets/3d7cafdb-eef0-4b8d-bb50-8e3ea01e7160)

### Source Code Analysis
Inside of the source code, we can see the API code. Specifically, we can see how it returns the response.

![image](https://github.com/user-attachments/assets/b8afc598-d079-421f-82e4-0edd1f68f8a3)

We can see that it tries to eval() the content returned by the model. If it is successful, it returns it. If it throws an error,
it returns the raw content that was returned by the model.

This gives us a clear goal. We simply need to trick the LLM into responding with javascript code that reads in the flag content.

### API Analysis
Using Burp Suite, we can see the exact request made to the API endpoint.

![image](https://github.com/user-attachments/assets/80704df7-0dd2-478c-84b7-3829d2b9216d)

We see a standard LLM request with system, assistant, and user messages. We all see the temperature and max_tokens options.

In a standard LLM interaction, the system defines the context with which to interpret the conversation, the user provides the query, 
and the assistant is what the user is responding to. The temperature controls the randomness of the model’s output, 
with lower values producing less random responses.

In order to read in the flag value via eval() we can try to make it return the following statement:

```js
const fs = require('fs'); fs.readFileSync('flag.txt', 'utf8');
```

To do this, we can rewrite the system role (which is the role that sets the context of the conversation) to make it so that the
LLM simply returns exactly the user input. We will also set the temperature to 0 to make it as deterministic as possible.

![image](https://github.com/user-attachments/assets/904aeb2c-d902-4d52-8d09-93d6191c6dd8)

This successfully responds with the flag:

![image](https://github.com/user-attachments/assets/19b21ce0-c07c-413c-bf6d-87cab328bd47)


# Important Concepts
- LLM Prompt Tampering
- LLM Inputs
