# (web) amogsus-api

## Introduction
This is an beginner/intermediate level SQL Injection challenge that required the participant to know well how to manuever SQL queries and to understand how they're formed, as well as the interaction between the web application and the SQL database.
It's a challenge which has two major ways of being solved: 
- By using triple quotes during the SQL injection phase
- By hijacking an existing account using the user ID during the SQL injection phase

https://ctftime.org/event/2052

## Guessing the type of vulnerability
Opening the `.zip` archive we were given, we are able to see three files: `main.py`, `database.db` and the `flag.txt` file. We shall start by looking at `main.py`, which will indicate to us how the web server works.
Opening the `main.py` file, we see that there's plenty imports. We know we are faced with a `flask` application that utilizes `SQL`. This indicates that the challenge might involve some type of SQL injection attack. We have the confirmation of this on these lines of code:
```python
@app.route('/', methods=['GET'])
def index():
  return jsonify({'message': 'Welcome to the amogsus API! I\'ve been working super hard on it in the past few weeks. You can use a tool like postman to test it out. Start by signing up at /signup. Also, I think I might have forgotten to sanatize an input somewhere... Good luck!'})
  ```

## Finding the vulnerability
Finding SQL injection vulnerabilities is heavily correlated with finding unsanitized input parameters. So we must immediately ask ourselves how the python script interacts with the SQL file present in the same folder. In this context, we see that parameterized statements utilize `cursor.execute`, in the form `cursor.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))`. This is parameterized since we see that the parameters are represented by `?` and the user input is handled by the function so that SQL injection is not possible. Therefore, we'll try to find a line with a SQL query that doesn't use `cursor.execute` like this.
On line 93, we see the following:
```python
cursor.execute(f'UPDATE users SET username="{username}", password="{password}" WHERE username="{session["username"]}"')
```
This is vulnerable to SQL injection, since user input is sent together with the query without any type of sanitation. Contrary to what we saw previously, this line utilizes Python 3 `f-strings` to send the SQL query, instead of giving them separately as parameters.
From now on, we must ask ourselves how to reach this point in the code. 
But first, it's important for us to understand the web application. Those `@app.route('/login', methods=['POST'])` lines are very important, since they indicate how we are able to access them. If, for instance, the URL was `example.com`, we would be able to visit the `/login` route by using a `POST` request. 
Therefore, by looking that those `@app.route` lines, we see that the server contains:
- `/`
- `/signup`
- `/login`
- `/account`
- `/account/update` (where the vulnerability is)
- `/flag`
Our browser utilizes `GET` requests if we visit it using the search bar. To change the request method, we will have to fire up Burp Suite.

## Getting to the vulnerable route
Let's start by signing-up to the application. As we saw previously, we are going to send a POST request to the application. If this is not something you are very familiar with, it might the best for you to execute `main.py` (don't forget to install the dependencies and to change the port so it doesn't conflict with the default `8080` port in burp) and try to exploit it locally first before moving to the actual server. For educational purposes, this is the approach I will use on this article. I use PyCharm Community as my IDE of preference.

![](Images/Pasted%20image%2020230809172105.png?raw=true)

We are able to see the requests we make if we open `http://192.168.1.10:2000` in our browser.

![](Images/Pasted%20image%2020230809172241.png?raw=true)

As we saw previously, by going to `/signup` we are presented with the following message:

![](Images/Pasted%20image%2020230809172357.png?raw=true)

Therefore, we are going to capture this request with our Burp proxy and change it to the method the application requires and send it to Repeater so that we can ditch the browser. 

![](Images/Pasted%20image%2020230809172546.png?raw=true)

Looking at the code, we see the following:
```python
data = request.form  
# ...
username = data['username']  
password = data['password']
```

This means we have to provide the application with the parameters username and password as form data. As such, when altering the request, we must not forget to include the following in our header: 

![](Images/Pasted%20image%2020230809172948.png?raw=true)

Otherwise, if we send form data (below),

![](Images/Pasted%20image%2020230809173011.png?raw=true)

We will receive a `500 Internal Server Error` response. By looking at what the server printed (on our side), it has outputted 
```python
werkzeug.exceptions.BadRequestKeyError: 400 Bad Request: The browser (or proxy) sent a request that this server could not understand.
```
Which makes since, since we did not provide what `Content-Type` the `POST` data we are sending is.
Our final request to signup should look similar to this:

![](Images/Pasted%20image%2020230809173446.png?raw=true)

If we hit send, we're going to receive a `200 OK` message with `JSON` data telling us that the User was created and that we can now login. What I recommend at this stage is to send the request to Repeater every API endpoint, which permits us to signup, login, and so on, much faster, which is something especially good for trial-and-error.

![](Images/Pasted%20image%2020230809173640.png?raw=true)

Changing `POST /signup` to `POST /login`, we receive the following message
![](Images/Pasted%20image%2020230809174023.png?raw=true)

The token is associated with our login session, and we definitely have to use it if we want to get to `/account` or `/account/update`. However, since we don't know yet how to use it, let's go back to the code.
We see that on `/account`, the following lines refer to the token:
```python
token = request.headers.get('Authorization', type=str)  
token = token.replace('Bearer ', '')
```
The first line indicates to us that it is looking for a header named `Authorization`. Therefore, we must add to our burp request the following: 

![](Images/Pasted%20image%2020230809174540.png?raw=true)

Notice that having `Bearer ` or not makes no difference, as this is something removed in the line right after. This has to do with the already defined [HTTP authentication frameworks](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) 

By requesting `/account`, the server replies with the following message:

![](Images/Pasted%20image%2020230809174944.png?raw=true)

Since we need to be `sus` to be able to get `/flag`, this means we must alter `sus` to `1`, which is truthy (not a joke!), that is, something that evaluate to True in a boolean context. We are able to change this due to the SQL injection vulnerability over at `/account/update`.
In order to do this, we must understand the basics of SQL injection well. Looking at the code,
```python
def update():  
    with sqlite3.connect('database.db') as con:  
        cursor = con.cursor()  
        token = request.headers.get('Authorization', type=str)  
        token = token.replace('Bearer ', '')  
        if token:  
            for session in sessions:  
                if session['token'] == token:  
                    data = request.form  
                    username = data['username']  
                    password = data['password']  
                    if (username == '' or password == ''):  
                        return jsonify({  
                                           'message': 'Please provide your new username and password as form-data or x-www-form-urlencoded!'})  
                    print(f'UPDATE users SET username="{username}", password="{password}" WHERE username="{session["username"]}"')  
                    cursor.execute(  
                        f'UPDATE users SET username="{username}", password="{password}" WHERE username="{session["username"]}"')  
                    con.commit()  
                    session['username'] = username  
                    return jsonify({'message': 'Account updated!'})  
            return jsonify({'message': 'Invalid token!'})  
        else:  
            return jsonify({'message': 'Please provide your token!'})
```
We see that we must send the username and the password arguments like we did when we were signing up, otherwise it will return a message. Then, we must pay attention to this query:
```python
cursor.execute(  
    f'UPDATE users SET username="{username}", password="{password}" WHERE username="{session["username"]}"')
```

At this point, we realize that the application doesn't unquote the values we have sent while signing up, which is where the catch is at. We are able to confirm this if we open the `.db` file using `DB Browser`. 

![](Images/Pasted%20image%2020230809180303.png?raw=true)

If we don't realize this, we are going to have a problem injecting SQL. From now on, one could have two approaches:
- Hijack a record using the id and change the username, password and sus
- Using triple-quotes (since using `username="user1"` wont work: this query is referring to a user stored as `user1` in the database, not `"user1"`)

By looking at the query again, we are able to control everything that comes after `UPDATE users SET username="`. We will comment out the rest using `-- -`

## Using triple-quotes

![](Images/Pasted%20image%2020230809181349.png?raw=true)

Remember that since the values are unquoted, the first `"` will also be present in the SQL query, as you can spot in the printed query that was sent by the web application:
```
UPDATE users SET username="""user1""",password="password",sus=1 WHERE username="""user1"""-- -"", password=""password"" WHERE username=""user1""
```
This way, we are able to login as `username="user1"&password="password"`, like we did at the start.
## Using the ID

![](Images/Pasted%20image%2020230809182051.png?raw=true)

Another way, wrapping everything is just double-quotes, would be to hijack a user (in this case of `id=1`) and change it so that we are able to login with new credentials and `sus=1`. In this case, the query is:
```
UPDATE users SET username="",password='',sus=1 WHERE id=1 -- -"", password="'password'" WHERE username="",password='',sus=1 WHERE id=1 -- -""
```
And the credentials will be stored as _nothing_. 

![](Images/Pasted%20image%2020230809182346.png?raw=true)

This way, we are able to login by providing _nothing_ to `/login`, or empty arguments.

![](Images/Pasted%20image%2020230809182541.png?raw=true)

Response:

![](Images/Pasted%20image%2020230809182554.png?raw=true)

## Getting the flag
Now that we have successfully exploited the SQL injection vulnerability, we just have to do a `GET` request to `/flag`, and retrieve it.

![](Images/Pasted%20image%2020230809182718.png?raw=true)

Now we simply have to do to exact same steps on the live web application, and submit it on the CTF web-page.

## Acknowledgement
  
Hats off to the LITCTF team! Your dedication was something that I found very distinctive and that shone not only through the active and caring Discord engagement but also in the design of the CTF itself. The wide range of challenges catered to participants of all levels, which I found very considerative. Well done and I'm definitely looking forward to next year's edition!
