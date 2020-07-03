package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

const (
	SECRET_TOCKEN_ACCECC = "4234kxzjcjj3nxnxbcvsjfj"
	TokenResetField      = "TokenReset"
)

var (
	client *mongo.Client
	db     *mongo.Database
	col    *mongo.Collection
	ctx    context.Context
)

type AuthTokens struct {
	TokenAccess, TokenReset, Guid string
}

func init() {
	ctx = context.Background()
	clientOpts := options.Client().ApplyURI("mongodb://mongo:27017,mongo1:27018,mongo3:27019/?authSource=admin&replicaSet=rs0")
	var err error
	client, err = mongo.Connect(ctx, clientOpts)
	if err != nil {
		fmt.Println(err)
		return
	}
	db = client.Database("authDB")
	col = db.Collection("usersToken")
	fmt.Println("Connect to db: " + db.Name() + " Connect to col: " + col.Name())
}
func HandleGenerate(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("GUID")
	if userId == "" {
		http.Error(w, "user id need", http.StatusBadRequest)
		return
	}
	authTokens, err := CreateTokens(userId, SECRET_TOCKEN_ACCECC)
	if err != nil {
		http.Error(w, "err when created tokens", http.StatusInternalServerError)
		return
	}
	jData, err := json.Marshal(authTokens)
	if err != nil {
		http.Error(w, "err when created tokens", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}
func HandleRefresh(w http.ResponseWriter, r *http.Request) {
	userId := r.URL.Query().Get("GUID")
	TokenReset := r.URL.Query().Get(TokenResetField)
	if userId == "" || TokenReset == "" {
		http.Error(w, "user id need and token and token should be correct", http.StatusBadRequest)
		return
	}
	authTokens, err := UpdateByTokenReset(TokenReset, SECRET_TOCKEN_ACCECC)
	if err != nil {
		http.Error(w, "err when created tokens", http.StatusInternalServerError)
		return
	}
	jData, err := json.Marshal(authTokens)
	if err != nil {
		http.Error(w, "err when created tokens", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jData)
}
func main() {
	http.HandleFunc("/generate", HandleGenerate)
	http.HandleFunc("/refresh", HandleRefresh)
	log.Fatal(http.ListenAndServe(":80", nil))
}

func GetDefaultEncoder(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}
func CreateTokens(userId, secret string) (*AuthTokens, error) {
	authTokens := new(AuthTokens)
	tmpHeader := GetDefaultEncoder([]byte(`{"alg":"HS512","typ":"JWT"}`))
	//TODO REMOVE " in userId
	payload := GetDefaultEncoder([]byte(`{"userId":"` + userId + `"}`))
	tmpHeaderANDpayload := tmpHeader + "." + payload

	h := hmac.New(sha512.New, []byte(secret))
	h.Write([]byte(tmpHeaderANDpayload))

	authTokens.Guid = userId
	authTokens.TokenAccess = tmpHeaderANDpayload + "." + GetDefaultEncoder(h.Sum(nil))
	//TODO make function isNonExistTokenReset
	rb := make([]byte, 50)
	_, err := rand.Read(rb)
	if err != nil {
		return nil, err
	}
	authTokens.TokenReset = GetDefaultEncoder(rb)
	// insert in mongo
	if err := authTokens.InsertTokenReset(); err != nil {
		return nil, err
	}
	return authTokens, nil
}
func UpdateByTokenReset(TokenReset string, secret string) (*AuthTokens, error) {
	TokenResetHash, err := makeTokenResetHash(TokenReset)
	if err != nil {
		return nil, err
	}
	err = db.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) (err error) {
		defer func() {
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
			} else {
				sessionContext.CommitTransaction(sessionContext)
			}
		}()
		err = sessionContext.StartTransaction()
		if err != nil {
			fmt.Println(err)
			return err
		}
		one, err := col.DeleteOne(sessionContext, bson.M{TokenResetField: TokenResetHash})
		if err != nil {
			return err
		}
		if one.DeletedCount == 0 {
			return errors.New("bad token")
		}

		return
	})
	return nil, err
}
func (t *AuthTokens) InsertTokenReset() error {
	TokenResetHash, err := makeTokenResetHash(t.TokenReset)
	if err != nil {
		return err
	}
	err = db.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			fmt.Println(err)
			return err
		}
		_, err = col.InsertOne(sessionContext, bson.M{"guid": t.Guid, TokenResetField: TokenResetHash})
		if err != nil {
			sessionContext.AbortTransaction(sessionContext)
			fmt.Println(err)
			return err
		}
		return sessionContext.CommitTransaction(sessionContext)
	})
	return err
}
func makeTokenResetHash(t string) (string, error) {
	TokenResetHash, err := bcrypt.GenerateFromPassword([]byte(t), 20)
	if err != nil {
		return "", err
	}
	return string(TokenResetHash), nil
}
