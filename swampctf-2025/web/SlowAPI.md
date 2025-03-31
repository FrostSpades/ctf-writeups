# SlowAPI
Writeup by: Ethan Andrews (UofUsec)

## Description
The Gator Research Institute asked me to develop an app for them. I've been hearing a lot of hullabaloo recently about Next.js, so I decided to make my app inspired by their code. Can you see if you can access the flag? Authentication hasn't been implemented yet, so you'll need to find a way around it.

## Writeup
### Initial Looks
We are greeted with a website that appears to host an API. It says that the authentication system is under construction.
We can also see the Secret Flag button in the menu.

![image](https://github.com/user-attachments/assets/c278c110-a4a0-4547-aa09-2207d4800f71)

Traveling to the Secret flag, we get the following hint: Only swamp creatures can access this page. Maybe there's a way to convince the API that you're a server-side middleware process...

![image](https://github.com/user-attachments/assets/a2fbc929-0987-4174-807e-e1b311446a21)

### Burp Suite Analysis
We can analyze how the API call actually works using Burp Suite. This is done by analyzing the http requests that occur
when traveling to the `/flag` path.

In Burp Suite, we can see the exact api call that occurs. It appears to occur at the `/api/protected/flag` endpoint.

![image](https://github.com/user-attachments/assets/0e16400d-81e2-4bf2-aaa0-dc5f93f58150)

This is further verified by traveling to this endpoint in the web browser:

![image](https://github.com/user-attachments/assets/4dd461f7-d001-4329-87f2-6dbd2e30d435)

Now that we know the endpoint, we can start to think about how to exploit it.

### Middleware Spoofing
The hint states that we need to some how trick the API into thinking we are a server-side middleware process.

After doing some research, we can find an explanation of this exact vulnerability ([Next.js Middleware Auth Bypass](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/)).

Apparently, when the `x-middleware-subrequest` header is added to the http request, it tricks the server into thinking we
are middleware.

Using Burp Suite, we can add this header to our request.

![image](https://github.com/user-attachments/assets/6c285f6d-bf8f-480c-93e0-9fcbfc481be6)

This returns the flag.

![image](https://github.com/user-attachments/assets/273ba32a-b1f2-41cb-a546-c0b796c5a705)

## Important Concepts
- API
- Burp Suite
- nextjs middleware
- `https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/`
