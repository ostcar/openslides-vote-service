<!--- Code generated with go generate ./... DO NOT EDIT. --->
# Configuration

## Environment Variables

The Service uses the following environment variables:

* `VOTE_PORT`: Port on which the service listen on. The default is `9013`.
* `MESSAGE_BUS_HOST`: Host of the redis server. The default is `localhost`.
* `MESSAGE_BUS_PORT`: Port of the redis server. The default is `6379`.
* `DATASTORE_DATABASE_USER`: Postgres User. The default is `openslides`.
* `OPENSLIDES_DEVELOPMENT`: If set, the service uses the default secrets. The default is `false`.
* `DATASTORE_DATABASE_HOST`: Postgres Host. The default is `localhost`.
* `DATASTORE_DATABASE_PORT`: Postgres Post. The default is `5432`.
* `DATASTORE_DATABASE_NAME`: Postgres Database. The default is `openslides`.
* `AUTH_PROTOCOL`: Protocol of the auth service. The default is `http`.
* `AUTH_HOST`: Host of the auth service. The default is `localhost`.
* `AUTH_PORT`: Port of the auth service. The default is `9004`.
* `AUTH_Fake`: Use user id 1 for every request. Ignores all other auth environment variables. The default is `false`.
* `VOTE_REDIS_HOST`: Host of the redis used for the fast backend. The default is `localhost`.
* `VOTE_REDIS_PORT`: Port of the redis used for the fast backend. The default is `6370`.
* `VOTE_DATABASE_USER`: Databasename of the postgres database used for long polls. The default is `postgres`.
* `VOTE_DATABASE_HOST`: Host of the postgres database used for long polls. The default is `localhost`.
* `VOTE_DATABASE_PORT`: Port of the postgres database used for long polls. The default is `5432`.
* `VOTE_DATABASE_NAME`:  The default is ``.
* `VOTE_BACKEND_FAST`: The backend used for fast polls. Possible backends are redis, postgres or memory. The default is `redis`.
* `VOTE_BACKEND_LONG`: The backend used for long polls. The default is `postgres`.


## Secrets

Secrets are filenames in the directory `SECRETS_PATH` (default: `/run/secrets/`). 
The service only starts if it can find each secret file and read its content. 
The default values are only used, if the environment variable `OPENSLIDES_DEVELOPMENT` is set.

* `postgres_password`: Postgres Password. The default is `openslides`.
* `auth_token_key`: Key to sign the JWT auth tocken. The default is `auth-dev-token-key`.
* `auth_cookie_key`: Key to sign the JWT auth cookie. The default is `auth-dev-cookie-key`.
