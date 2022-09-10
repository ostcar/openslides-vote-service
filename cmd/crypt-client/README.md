# crypt-client

The crypt client helps to create encrypted votes to test the vote decryp service.

Usage:

crypt-client POLL_KEY vote

The POLL_KEY is the return value from the start-call of the vote-service

```
curl localhost:9013/internal/vote/start?id=1 -X POST
{"public_key":"kvCzesgjbU4cCIVKbrsnSBlYYq1i1En5UWMtZELSEVI=","public_key_sig":"eDq7IaUDI1/lkDaUrVtmjiFdOacwz4Vs+5xH5dUOGbJKHGPhjPN5QOeQbmCdhT9V9UrKKdfU5wv7zRy5upP2AA=="}
```

The vote has to be some data in json format. For example "Y". Make sure the quotation is handled correctly by the  shell.

For example:

```
crypt-client kvCzesgjbU4cCIVKbrsnSBlYYq1i1En5UWMtZELSEVI= '"Y"'
```

The returnvalue looks like this:

```
{"value":"2dqx+xPzHqQWd4KplfRkXE2LBSv5v7YNHD1eUy6Fyy8oqDKbv7jIoX/u70np1uFBbLAM9lp76iVNSinT+lOZ"}
```

It can be used as a vote to the vote-service. For example:

```
curl localhost:9013/system/vote?id=1 -d '{"value":"2dqx+xPzHqQWd4KplfRkXE2LBSv5v7YNHD1eUy6Fyy8oqDKbv7jIoX/u70np1uFBbLAM9lp76iVNSinT+lOZ"}'
```

For decoding, call:

```
curl localhost:9013/internal/vote/stop?id=1 -X POST
```

The return value looks like this:

```
{"votes":{"id":"example.com/1","votes":["Y"]},"signature":"ruguvwrpNo2jfM09by2GOdXl+McC22zqBQUb276m9tWGGlT7LuU8C6cP5c2ZRkX0RInb9eGLOhaLohHKjULaDw==","user_ids":[1]}
```

It contains the decrypted vote.
