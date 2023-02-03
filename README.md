# authbot : authentication helper 
authbot retrieves secrets from GCP Secret Manager or AWS Secret Cache, 
then requests tokens from a oauth2 provider and makes them available in a keyring

GCP Secret Manager access relies on GOOGLE_APPLICATION_CREDENTIALS

The number of secrets/auth tokens to fetch is configurable, set this in NUM_SECRETS env var
authbot checks if required environment variables exist and falls back to looking for them in *./conf.env* 
Secrets env vars are expected to start with SECRET_ID_1 and exist sequentially until NUM_SECRETS without skipping

authbot sends the content of the secret as the body in a HTTP POST request to the oauth2 provider specified in `TOKEN_URL_*`

If a `TOKEN_FIELD_*` is specified, that field in the auth provider response is stored in Secret.Token (an atomic string), otherwise the entire response body is stored

authbot.Load() returns a *[]Secret

Accessing the keyring:
```var (
	keyring *[]authbot.Secret
	err     error
)

func main() {
	keyring, err = authbot.Load()
	if err != nil {
		log.Fatal("auth retrieval error: %v", err)
	}
...
token := (*keyring)[0].Token.String()

```

`SECRET_STORE` : *GCP* or *AWS*

Environment variables example:
```
# SECRET STORE
SECRET_STORE=GCP
NUM_SECRETS=2
# SECRET MANAGER
PROJECT_ID=projectID
SECRET_ID_1=secretID1
SECRET_VERSION_1=1
SECRET_ID_2=secretID2
SECRET_VERSION_2=1
# AUTH
TOKEN_URL_1=https://auth.domain.com/oauth/token
TOKEN_FIELD_1=access_token
TOKEN_TYPE_1=BEARER
TOKEN_TYPE_2=APIKEY
```
