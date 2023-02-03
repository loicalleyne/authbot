package authbot

import (
	"context"
	"fmt"
	"io"
	"log"
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
	token         []byte
	url           string
	secretID      string
	secretVersion string
	tokenType     string
	tokenField    string
}

var (
	Keyring        []Secret
	secretCache, _ = secretcache.New()
)

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
			s.secretID = os.Getenv("SECRET_ID_" + cast.ToString(i))
			if s.secretID == "" {
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

			s.token, err = fetchGCPSecret(projectID, s.secretID, s.secretVersion)
			if err != nil {
				return fmt.Errorf("authcreds: error retrieving %v/version/%v: %v", s.secretID, s.secretVersion, err)
			}
			// add secret to keyring
			Keyring = append(Keyring, *s)
		}
		// launch goroutine to fetch bearer tokens or store API key
		for i := 0; i < len(Keyring); i++ {
			if Keyring[i].tokenType == "Bearer" {
				go authBearer(Keyring, i, "")
			} else {
				Keyring[i].Token.Store(string(Keyring[i].token))
			}
		}
	case "AWS":
		for i := 1; i <= int(secretCount); i++ {
			var err error
			s := new(Secret)
			s.secretID = os.Getenv("SECRET_ID_" + cast.ToString(i))
			if s.secretID == "" {
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
			token, err := fetchAWSSecret(s.secretID)
			if err != nil {
				return fmt.Errorf("authcreds: error retrieving AWS secret %v: %v", s.secretID, err)
			}
			s.token = []byte(token)

			// add secret to keyring
			Keyring = append(Keyring, *s)
		}
		// launch goroutine to fetch bearer tokens or store API key
		for i := 0; i < len(Keyring); i++ {
			if Keyring[i].tokenType == "BEARER" {
				go authBearer(Keyring, i, "")
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

func authBearer(Keyring []Secret, index int, overlap string) {
	s := Keyring[index]
	payload := strings.NewReader(string(s.token))
	req, err := retryablehttp.NewRequest("POST", s.url, payload)
	if err != nil {
		log.Println(err)
	}
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 2
	retryClient.RetryWaitMin = 10000000
	retryClient.Logger = nil

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Cache-Control", "no-cache")
	var expiry int64
	time.Sleep(cast.ToDuration(overlap))
	for {
		res, err := retryClient.Do(req)
		if err != nil {
			log.Println(err)
		}

		body, err := io.ReadAll(res.Body)
		if err != nil {
			log.Println(err)
		}
		res.Body.Close()
		jsonbody := string(body)
		if s.tokenField == "" {
			Keyring[index].Token.Store(jsonbody)
		} else {
			Keyring[index].Token.Store(gjson.Get(jsonbody, s.tokenField).Str)
		}
		expiry = gjson.Get(jsonbody, "expires_in").Int()
		d := time.Duration(expiry)
		time.Sleep(d * time.Second)
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
