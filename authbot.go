package authbot

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-secretsmanager-caching-go/secretcache"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/joho/godotenv"
	"github.com/spf13/cast"
	"github.com/tidwall/gjson"
	"go.uber.org/atomic"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

type Secret struct {
	Token         atomic.String
	CancelFunc    context.CancelFunc
	ErrorChan     chan error
	token         []byte
	url           string
	SecretID      string
	secretVersion string
	tokenType     string
	tokenField    string
}

var (
	Keyring        []Secret
	secretCache, _ = secretcache.New()
)

// Load gets authbot to retrieve the stored secret from GCP or AWS Secret Manager
// and stores the secret in keyring or launches the authorization renewal goroutines
// which will retrieve tokens and store them in keyring
func Load() error {
	secretLocation := os.Getenv("SECRET_STORE")
	if secretLocation == "" {
		_, e := os.Stat("./conf.env")
		if os.IsNotExist(e) {
			return fmt.Errorf("authbot: missing conf.env file and required envvars not defined")
		}
		err := godotenv.Load("./conf.env")
		if err != nil {
			return fmt.Errorf("authbot: error loading .env file and required envvars not defined: %v", err)
		}
		secretLocation = os.Getenv("SECRET_STORE")
		if secretLocation == "" {
			return fmt.Errorf("authbot: required envvars not defined")
		}
	}

	secretCount := cast.ToInt(os.Getenv("NUM_SECRETS"))

	if secretCount < 1 {
		return fmt.Errorf("authcreds package: missing or invalid env var: num_secrets")
	}

	switch secretLocation {
	case "GCP":
		projectID := os.Getenv("PROJECT_ID")
		for i := 1; i <= int(secretCount); i++ {
			var err error
			s := new(Secret)
			s.SecretID = os.Getenv("SECRET_ID_" + cast.ToString(i))
			if s.SecretID == "" {
				return fmt.Errorf("authcreds: missing secret_id")
			}
			s.secretVersion = os.Getenv("SECRET_VERSION_" + cast.ToString(i))

			// default to secret version 1 if unspecified
			if s.secretVersion == "" {
				s.secretVersion = "1"
			}

			s.tokenType = os.Getenv("TOKEN_TYPE_" + cast.ToString(i))
			if s.tokenType == "" {
				s.tokenType = "Bearer"
			} else {
				s.tokenType = "APIKEY"
			}

			if s.tokenType == "Bearer" {
				s.url = os.Getenv("TOKEN_URL_" + cast.ToString(i))
				if s.url == "" {
					return fmt.Errorf("authcreds package: missing env var: token_url_%v", cast.ToString(i))
				}
				s.tokenField = os.Getenv("TOKEN_FIELD_" + cast.ToString(i))
			}

			s.token, err = fetchGCPSecret(projectID, s.SecretID, s.secretVersion)
			if err != nil {
				return fmt.Errorf("authcreds: error retrieving %v/version/%v: %v", s.SecretID, s.secretVersion, err)
			}
			// add secret to keyring
			Keyring = append(Keyring, *s)
		}
		// launch goroutine to fetch bearer tokens or store API key
		for i := 0; i < len(Keyring); i++ {
			if Keyring[i].tokenType == "Bearer" {
				authCtx := context.Background()
				authCtx, authCancel := context.WithCancel(authCtx)
				Keyring[i].CancelFunc = authCancel
				errors := make(chan error, 0)
				Keyring[i].ErrorChan = errors
				go authBearer(authCtx, &Keyring, i)
			} else {
				Keyring[i].Token.Store(string(Keyring[i].token))
			}
		}
	case "AWS":
		for i := 1; i <= int(secretCount); i++ {
			var err error
			s := new(Secret)
			s.SecretID = os.Getenv("SECRET_ID_" + cast.ToString(i))
			if s.SecretID == "" {
				return fmt.Errorf("authcreds: missing secret_id")
			}

			s.tokenType = os.Getenv("TOKEN_TYPE_" + cast.ToString(i))
			if s.tokenType == "" {
				s.tokenType = "Bearer"
			} else {
				s.tokenType = "APIKEY"
			}

			if s.tokenType == "Bearer" {
				s.url = os.Getenv("TOKEN_URL_" + cast.ToString(i))
				if s.url == "" {
					return fmt.Errorf("authcreds package: missing env var: token_url_%v", cast.ToString(i))
				}
				s.tokenField = os.Getenv("TOKEN_FIELD_" + cast.ToString(i))
				if s.tokenField == "" {
					s.tokenField = "access_token"
				}
			}
			token, err := fetchAWSSecret(s.SecretID)
			if err != nil {
				return fmt.Errorf("authcreds: error retrieving AWS secret %v: %v", s.SecretID, err)
			}
			s.token = []byte(token)

			// add secret to keyring
			Keyring = append(Keyring, *s)
		}
		// launch goroutine to fetch bearer tokens or store API key
		for i := 0; i < len(Keyring); i++ {
			if Keyring[i].tokenType == "BEARER" {
				authCtx := context.Background()
				authCtx, authCancel := context.WithCancel(authCtx)
				Keyring[i].CancelFunc = authCancel
				errors := make(chan error, 0)
				Keyring[i].ErrorChan = errors
				go authBearer(authCtx, &Keyring, i)
			} else {
				Keyring[i].Token.Store(string(Keyring[i].token))
			}
		}
	}
	return nil
}

func fetchAWSSecret(secretID string) (string, error) {
	result, err := secretCache.GetSecretString(secretID)
	if err != nil {
		return result, err
	}
	return result, err
}

func fetchGCPSecret(projectID, secretID, secretVersion string) ([]byte, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup client: %v", err)
	}
	defer client.Close()

	accessRequest := &secretmanagerpb.AccessSecretVersionRequest{
		Name: "projects/" + projectID + "/secrets/" + secretID + "/versions/" + secretVersion,
	}
	result, err := client.AccessSecretVersion(ctx, accessRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %v", err)
	}

	return result.Payload.Data, nil
}

// authBearer is launched as a goroutine
func authBearer(ctx context.Context, Keyring *[]Secret, index int) {
	s := *Keyring

	payload := strings.NewReader(string(s[index].token))
	req, err := retryablehttp.NewRequest("POST", s[index].url, payload)
	if err != nil {
		s[index].ErrorChan <- err
	}
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 30
	retryClient.RetryWaitMin = 2 * time.Second
	retryClient.Logger = nil

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	var expiry int64
	for ctx.Err() == nil {
		resp, err := retryClient.Do(req)
		if err != nil {
			s[index].ErrorChan <- err
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s[index].ErrorChan <- err
			return
		}
		resp.Body.Close()
		jsonbody := string(body)
		// If response body token field is specified store it in keyring otherwise store entire response body
		if s[index].tokenField == "" {
			s[index].Token.Store(jsonbody)
			expiry = gjson.Get(jsonbody, "expires_in").Int()
		} else {
			s[index].Token.Store(gjson.Get(jsonbody, s[index].tokenField).Str)
		}
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
		s[index].Token.Store("")
	}
}

func TokenString(index int) (string, error) {
	if len(Keyring) < index+1 {
		return "", fmt.Errorf("token index %v not found", index)
	}
	return Keyring[index].Token.String(), nil
}

func TokenBytes(index int) ([]byte, error) {
	if len(Keyring) < index+1 {
		return nil, fmt.Errorf("token index %v not found", index)
	}
	return []byte(Keyring[index].Token.String()), nil
}
