# Javascript Puzzle
Created by: SamXML  
Writeup by: Ethan Andrews (UofUsec)

## Description
It is often useful to force exceptions to potentially get back valuable information.
Can you make a request which causes an exception in this app?

## Writeup
### Initial Looks
When going to the website, we are greeted with "Hello Guest", but nothing else appears on-screen.

![image](https://github.com/user-attachments/assets/0b35e978-6755-4bea-9225-3f1e80c8abba)

By analyzing the javascript code, we can see that there is a hidden username query field that we can set. This is how the hello message
gets constructed. If this method throws an error, we will receive the flag.

### General Information
#### Query Parameters
In order to set query parameters, we can set them inside the url:
```URL
https://website.com/?username=Ethan
```

![image](https://github.com/user-attachments/assets/5ec8f9dc-2cec-4bc0-aef4-a95aaa41944a)

But you can also assign complex types to these parameters. 

For example, you can set `username` to be an array using `[]`:
```URL
https://website.com/?username[]=Ethan&username[]=Andrews
```

![image](https://github.com/user-attachments/assets/f72c6449-15a7-4387-91ea-bbb1edb1fc57)

Another example is dictionaries:
```URL
https://website.com/?username['first']=Ethan&username['last']=Andrews
```

![image](https://github.com/user-attachments/assets/f50b232b-dd75-4714-83c4-272f1dbedcbd)

#### Javascript Strings
The way that javascript handles strings is by calling the objects toString() method which returns "[object Object]" by default.
This means that even if the toString() method isn't defined, it'll always return something. This makes it very tricky because
even if we set username to be a complex object, it'll still be converted to a valid string when appended with "Hello ".

![image](https://github.com/user-attachments/assets/5cee978b-4e8e-47b6-8493-de41e657795e)

### Solution
So we have determined that as long as javascript can execute username's toString method, the code can't realistically throw
an error.

Because of this, the solution becomes clear; we must override the toString method. We can set the username property to:
```URL
https://js-puzzle-974780027560.us-east5.run.app/?username[toString]=random
```
This statement creates a toString parameter that overrides the toString function so that when `toString()` is called, the function no longer exists 
and throws an error.

By doing this, we get the flag.

## Important Concepts
- Query Parameters
- Web Exploitation Error Exceptions
