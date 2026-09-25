<!--- Code generated with go generate ./... DO NOT EDIT. --->
# Configuration

## Environment Variables

The Service uses the following environment variables:

* `VOTE_PORT`: Port on which the service listens on. The default is `9013`.
* `MESSAGE_BUS_HOST`: Host of the redis server. The default is `localhost`.
* `MESSAGE_BUS_PORT`: Port of the redis server. The default is `6379`.
* `OPENSLIDES_DEVELOPMENT`: If set, the service uses the default secrets. The default is `false`.
* `DATABASE_PASSWORD_FILE`: Postgres Password. The default is `/run/secrets/postgres_password`.
* `DATABASE_HOST`: Postgres Host. The default is `localhost`.
* `DATABASE_PORT`: Postgres Post. The default is `5432`.
* `DATABASE_NAME`: Postgres User. The default is `openslides`.
* `DATABASE_USER`: Postgres Database. The default is `openslides`.
* `DATABASE_NOTIFY_PASSWORD_FILE`: Postgres Password for notify. The default is `DATABASE_PASSWORD_FILE`.
* `DATABASE_NOTIFY_HOST`: Postgres Host for notify. The default is `DATABASE_HOST`.
* `DATABASE_NOTIFY_PORT`: Postgres Port for notify. The default is `DATABASE_PORT`.
* `DATABASE_NOTIFY_NAME`: Postgres Database for notify. The default is `DATABASE_NAME`.
* `DATABASE_NOTIFY_USER`: Postgres User for notify. The default is `DATABASE_USER`.
* `AUTH_PROTOCOL`: Protocol of the auth service. The default is `http`.
* `AUTH_HOST`: Host of the auth service. The default is `localhost`.
* `AUTH_PORT`: Port of the auth service. The default is `9004`.
* `AUTH_FAKE`: Use user id 1 for every request. Ignores all other auth environment variables. The default is `false`.
* `AUTH_TOKEN_KEY_FILE`: Key to sign the JWT auth tocken. The default is `/run/secrets/auth_token_key`.
* `AUTH_COOKIE_KEY_FILE`: Key to sign the JWT auth cookie. The default is `/run/secrets/auth_cookie_key`.
* `VOTE_SECRET_KEY_FILE`: Path to the secret key for secret polls. The content of the file can be anything. Should be at least 32 bytes long. The default is `/run/secrets/vote_secret_key`.
