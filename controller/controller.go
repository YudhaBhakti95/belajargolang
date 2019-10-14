package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/YudhaBhakti95/belajargolang/config/db"
	"github.com/YudhaBhakti95/belajargolang/model"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

func checkPassStrength(pass string) bool {
	passwordLength := len(pass) >= 8 && len(pass) <= 15
	containsUppercase, _ := regexp.MatchString(`[A-Z]`, pass)
	containsLowerCase, _ := regexp.MatchString(`[a-z]`, pass)
	containsNumber, _ := regexp.MatchString(`[0-9]`, pass)

	return passwordLength && containsUppercase && containsLowerCase && containsNumber
}

func RegisterHandler(c *gin.Context) {
	var user model.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	var res model.ResponseResult

	if err != nil {
		res.Error = err.Error()
		c.JSON(http.StatusInternalServerError, res)
		return
	}

	collection, err := db.GetDBCollection()

	if err != nil {
		res.Error = err.Error()
		c.JSON(http.StatusInternalServerError, res)
		return
	}
	var result model.User
	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)

	if err != nil {
		if err.Error() == "mongo: no documents in result" {

			if !checkPassStrength(user.Password) {
				res.Error = "Error Not Strong Password"
				c.JSON(http.StatusBadRequest, res)
				return
			}

			hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 5)
			if err != nil {
				res.Error = "Error While Hashing Password, Try Again"
				c.JSON(http.StatusInternalServerError, res)
				return
			}
			user.Password = string(hash)

			_, err = collection.InsertOne(context.TODO(), user)
			if err != nil {
				res.Error = "Error While Creating User, Try Again"
				c.JSON(http.StatusInternalServerError, res)
				return
			}
			res.Result = "Registration Successful"
			c.JSON(http.StatusOK, res)
			return
		}
		res.Error = err.Error()
		c.JSON(http.StatusInternalServerError, res)
		return
	}
	res.Result = "Username already Exists!!"
	c.JSON(http.StatusInternalServerError, res)
	return
}

func LoginHandler(c *gin.Context) {
	var user model.User
	body, _ := ioutil.ReadAll(c.Request.Body)
	err := json.Unmarshal(body, &user)
	if err != nil {
		log.Fatal(err)
	}

	collection, err := db.GetDBCollection()

	if err != nil {
		log.Fatal(err)
	}
	var result model.User
	var res model.ResponseResult

	err = collection.FindOne(context.TODO(), bson.D{{"username", user.Username}}).Decode(&result)

	fmt.Println(body)

	if err != nil {
		res.Error = "Invalid username"
		c.JSON(http.StatusInternalServerError, res)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(user.Password))

	if err != nil {
		res.Error = "Invalid password"
		c.JSON(http.StatusInternalServerError, res)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":  result.Username,
		"firstname": result.FirstName,
		"lastname":  result.LastName,
	})

	tokenString, err := token.SignedString([]byte("secret"))

	if err != nil {
		res.Error = "Error while generating token,Try again"
		c.JSON(http.StatusInternalServerError, res)
		return
	}

	result.Token = tokenString
	result.Password = ""

	c.JSON(http.StatusOK, result)
}

func ProfileHandler(c *gin.Context) {
	var result model.User
	var res model.ResponseResult
	reqToken := c.Request.Header.Get("Authorization")

	if !strings.Contains(reqToken, "Bearer") {
		res.Error = "Invalid Token"
		c.JSON(http.StatusBadRequest, res)
		return
	}
	reqToken = strings.Replace(reqToken, "Bearer ", "", -1)
	token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method")
		}
		return []byte("secret"), nil
	})

	if err != nil {
		res.Error = err.Error()
		c.JSON(http.StatusBadRequest, res)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		result.Username = claims["username"].(string)
		result.FirstName = claims["firstname"].(string)
		result.LastName = claims["lastname"].(string)
		c.JSON(http.StatusOK, result)
		return
	}
	res.Error = err.Error()
	c.JSON(http.StatusBadRequest, res)

}
