package simpleauthmysql

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/johndunne/pat"
	//"github.com/gorilla/sessions"

	fb "github.com/huandu/facebook"
	"io"
	"net/http"
	"regexp"
	"time"
	"github.com/go-errors/errors"
	"github.com/gorilla/context"
	"fmt"
	"github.com/jinzhu/gorm"
	"math/rand"
	"log"
	"strconv"
	"golang.org/x/crypto/bcrypt"
	"github.com/gorilla/sessions"
	"github.com/gorilla/securecookie"
	"io/ioutil"
	"os"
	"strings"
)

type EmailConfig struct {
	Username string
	Password string
	Host     string
	Port     int
}

func SetupNonSecureAuthConfig( the_cook_auth_name string ,cookie_store_string string, secret_salt string){
	cookie_store = sessions.NewCookieStore([]byte(cookie_store_string))
	salt = secret_salt
	cook_auth_name = the_cook_auth_name
}

func SetupSecureAuthConfig( the_cook_auth_name string ){
	var hashKey []byte
	if _, err := os.Stat(SECURE_COOKIE_HASH_FILE); os.IsNotExist(err) {
		hashKey = securecookie.GenerateRandomKey(32)
		if e:=ioutil.WriteFile(SECURE_COOKIE_HASH_FILE,hashKey,0644);e!=nil{
			panic(e)
		}
	} else if secure_bytes, err := ioutil.ReadFile(SECURE_COOKIE_HASH_FILE);err!=nil{
		panic(err)
	}else{
		hashKey = secure_bytes
	}

	var blockKey []byte
	if _, err := os.Stat(SECURE_COOKIE_BLOCK_FILE); os.IsNotExist(err) {
		blockKey = securecookie.GenerateRandomKey(32)
		if e:=ioutil.WriteFile(SECURE_COOKIE_BLOCK_FILE,blockKey,0644);e!=nil{
			panic(e)
		}
	} else if secure_bytes, err := ioutil.ReadFile(SECURE_COOKIE_BLOCK_FILE);err!=nil{
		panic(err)
	}else{
		blockKey = secure_bytes
	}
	secure_cookie_store = securecookie.New(hashKey, blockKey)
	salt = string(hashKey)
	cook_auth_name = the_cook_auth_name
}

const MIN_GUEST_USERNAME_LENGTH = 30
var cookie_store *sessions.CookieStore
var secure_cookie_store *securecookie.SecureCookie
var salt string
var cook_auth_name string // This is the cookie name, visible in all http requests and responses
var SECURE_COOKIE_HASH_FILE = "secure_cookie_hash"
var SECURE_COOKIE_BLOCK_FILE = "secure_cookie_block"

func SetupAuthServer(mx *pat.Router) {
	if gorm_db == nil {
		panic(errors.New("userauth needs a gorm_db instance defined."))
	} else if cookie_store==nil && secure_cookie_store == nil{
		panic(errors.New("Use the SetupSimpleAuthConfig function to setup the secret sauces."))
	} else if len(salt)==0{
		panic(errors.New("Use the SetupSimpleAuthConfig function to setup the secret sauces, salt is missing."))
	}

	gorm_db.CreateTable(&User{})
	gorm_db.CreateTable(&ApiCall{})
	gorm_db.CreateTable(&ApiKey{})
	gorm_db.CreateTable(&ApiKeyMonthLimits{})
	gorm_db.AutoMigrate(&User{})
	gorm_db.AutoMigrate(&ApiCall{})
	gorm_db.AutoMigrate(&ApiKey{})
	gorm_db.AutoMigrate(&ApiKeyMonthLimits{})
	gorm_db.AutoMigrate(&UserMeta{})

	//h := sha256.New()
	//io.WriteString(h, salt)
	//io.WriteString(h, "test")
	//io.WriteString(h, salt)
	//Trace.Printf("%s", hex.EncodeToString(h.Sum(nil)))

	mx.Post("/fb_signin", SigninFacebookAccountHandler)
	mx.Post("/fb_signup", CreateOrSigninFacebookAccountHandler)
	mx.Post("/signup", SignupToAccountHandler)
	mx.Post("/signin", SigninToAccountHandler)
	mx.Post("/updatenote", AddPushNoteToAccountHandler)
	mx.Get("/signout", SignOutOfAccountHandler)
	mx.Get("/me", MeHandler)
	mx.Post("/request-guestid", SuggestGuestUserIDHandler)
	mx.Post("/request-apikey", RequestApiKey)
	mx.Post("/verify", VerifyAccountSignup )
	mx.Post("/resetpassword", ResetPassword)
	mx.Post("/newpassword", ChoosePassword)
	mx.Get("/user_meta", GetUserMeta) // curl "http://127.0.0.1:1243/user_meta" -H 'Cookie: cheerychow=MTQ3MDMxOTA0MXxEdi1CQkFFQ180SUFBUkFCRUFBQUtmLUNBQUVHYzNSeWFXNW5EQklBRUhOcFoyNWxaRjlwYmw5MWMyVnlhV1FGYVc1ME5qUUVBZ0FDfA0-H2m-GYIf-HnPB3PJJImT0BebCthc0bG2uZduSFAr' -H 'Origin: https://feastmachine.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36' -H 'Content-Type: application/json; charset=utf-8' -H 'Accept: */*' -H 'Referer: https://feastmachine.com/myaccount?meal-planner' -H 'Apikey: tAJlVs1aZBrEXiMC04CcOVmoVlccmvvEmfzgHdFhmepcVQ9RsG' -H 'Connection: keep-alive' --compressed
	mx.Get("/user_meta/{fields}", GetUserMeta) // curl "http://127.0.0.1:1243/user_meta/age" -H 'Cookie: cheerychow=MTQ3MDMxOTA0MXxEdi1CQkFFQ180SUFBUkFCRUFBQUtmLUNBQUVHYzNSeWFXNW5EQklBRUhOcFoyNWxaRjlwYmw5MWMyVnlhV1FGYVc1ME5qUUVBZ0FDfA0-H2m-GYIf-HnPB3PJJImT0BebCthc0bG2uZduSFAr' -H 'Origin: https://feastmachine.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36' -H 'Content-Type: application/json; charset=utf-8' -H 'Accept: */*' -H 'Referer: https://feastmachine.com/myaccount?meal-planner' -H 'Apikey: tAJlVs1aZBrEXiMC04CcOVmoVlccmvvEmfzgHdFhmepcVQ9RsG' -H 'Connection: keep-alive' --compressed
	mx.Put("/user_meta", SaveUserMeta) // curl "http://127.0.0.1:1243/user_meta" -X PUT -d '[{"key":"age","value":"38"}]' -H 'Cookie: cheerychow=MTQ3MDMxOTA0MXxEdi1CQkFFQ180SUFBUkFCRUFBQUtmLUNBQUVHYzNSeWFXNW5EQklBRUhOcFoyNWxaRjlwYmw5MWMyVnlhV1FGYVc1ME5qUUVBZ0FDfA0-H2m-GYIf-HnPB3PJJImT0BebCthc0bG2uZduSFAr' -H 'Origin: https://feastmachine.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36' -H 'Content-Type: application/json; charset=utf-8' -H 'Accept: */*' -H 'Referer: https://feastmachine.com/myaccount?meal-planner' -H 'Apikey: tAJlVs1aZBrEXiMC04CcOVmoVlccmvvEmfzgHdFhmepcVQ9RsG' -H 'Connection: keep-alive' --compressed
	mx.Put("/user", SaveUser) // curl "http://127.0.0.1:1243/user" -X PUT -d '[{"last_name":"Burke"}]' -H 'Cookie: cheerychow=MTQ3MDMxOTA0MXxEdi1CQkFFQ180SUFBUkFCRUFBQUtmLUNBQUVHYzNSeWFXNW5EQklBRUhOcFoyNWxaRjlwYmw5MWMyVnlhV1FGYVc1ME5qUUVBZ0FDfA0-H2m-GYIf-HnPB3PJJImT0BebCthc0bG2uZduSFAr' -H 'Origin: https://feastmachine.com' -H 'Accept-Encoding: gzip, deflate, sdch, br' -H 'Accept-Language: en-US,en;q=0.8' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36' -H 'Content-Type: application/json; charset=utf-8' -H 'Accept: */*' -H 'Referer: https://feastmachine.com/myaccount?meal-planner' -H 'Apikey: tAJlVs1aZBrEXiMC04CcOVmoVlccmvvEmfzgHdFhmepcVQ9RsG' -H 'Connection: keep-alive' --compressed
}

var userIDEmailerChan chan bool
var userIDFetcherChan chan string
var userFetcherChan chan *User
var apiKeyUniqueIDFetcherChan chan int64
var apiKeyFetcherChan chan *ApiKey

func StartUserFetcher() {
	go func() {
		if gorm_db == nil {
			panic(errors.New("userauth needs a gorm_db instance defined."))
		}
		userIDFetcherChan = make(chan string, 10)
		userFetcherChan = make(chan *User, 10)
		for {
			//Trace.Println("Waiting....")
			select {
			case new_handle_name := <-userIDFetcherChan:
				Trace.Println("Fetching user with ID: " + new_handle_name)
				user := User{}
				if err := gorm_db.Where("handle = ?", new_handle_name).First(&user).Error; err != nil {
					if err == gorm.ErrRecordNotFound {
						Trace.Println("No user with ID so creating: " + new_handle_name)
						if err := gorm_db.Debug().Where(User{Handle:new_handle_name}).Attrs(&User{Source:"chrome", Handle:new_handle_name}).FirstOrCreate(&user).Error; err != nil {
							panic(err)
							userFetcherChan <- nil
						}

					}else {
						panic(err)
					}
				}
				userFetcherChan <- &user
			}
		}
	}()
}

func StartUserEmailer() {
	go func() {
		if gorm_db == nil {
			panic(errors.New("userauth needs a gorm_db instance defined."))
		}
		userIDEmailerChan = make(chan bool, 10)
		for {
			//Trace.Println("Waiting....")
			select {
			case <-userIDEmailerChan:
			case <-time.After(time.Second * 10):
			}
			users := make([]User, 0)
			if err := gorm_db.Where("verify_sent = 0").Find(&users).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					panic(err)
				}
			}
			for _, user := range users {
				body_data := map[string]string{
					"name":user.FirstName,
					"confirm_url":"https://feastmachine.com/verify?code=" + user.VerifyCode,
					"confirm_code":user.VerifyCode,
				}
				if _, err:=SendEmail(Email{From:"admin@feastmachine.com", To:[]string{user.Email}, Subject: "Confirm your feastmachine.com account", BodyData:body_data}, "views/emails/confirm_account.tpl");err!=nil{
					fmt.Errorf("%s\n", err.Error())
				}else{
					if e:=gorm_db.Debug().Exec("UPDATE user SET verify_sent = 1 WHERE user_id = ?", user.User_id).Error;err!=nil{
						fmt.Errorf("%s\n", e.Error())
					}
				}
			}
		}

	}()
}

func StartAPIKeyFetcher() {
	go func() {
		if gorm_db == nil {
			panic(errors.New("userauth needs a gorm_db instance defined."))
		}
		apiKeyUniqueIDFetcherChan = make(chan int64, 10)
		apiKeyFetcherChan = make(chan *ApiKey, 10)
		for {

			select {
			case logged_in_user_id := <-apiKeyUniqueIDFetcherChan:
				var apiKey *ApiKey
				looking := true
				for ; looking; {
					//Trace.Println("Received api key request..")
					api_key_name := RandSeqOfAlphaChars(50)
					var api_key ApiKey
					if err:=gorm_db.Debug().Where("api_key = ?", api_key_name).First(&api_key).Error;err!=nil{
						if gorm.ErrRecordNotFound!=err {
							panic(err)
						}
					}

					if api_key.Api_key_id == 0 {
						apiKey = &ApiKey{Api_key:api_key_name, Valid:true, Created:time.Now().Unix(), Owner_id: logged_in_user_id, Expires:time.Now().Add(365 * 24 * 3600 * 1e9).Unix()}
						if create_error := gorm_db.Create(&apiKey).Error; create_error != nil {
							panic(create_error)
						}
						looking = false
					}
				}
				apiKeyFetcherChan <- apiKey
			}
		}
	}()
}


/**
 * There's a subtle yet distinct difference between an authenticated and authorised user. The authenticated user has signed in with their
 * username and password. This is stored in the session. An authorised user is a user determind to be authorised via their Api key. So,
 * it could be an app authorised with ab API key provided by the user.
 */
func GetAuthenticatedUser(r *http.Request) int64 {
	// Get a session.
	if cookie_store != nil {
		cookie_session, _ := cookie_store.Get(r, cook_auth_name)
		// Get the previously flashes, if any.
		if val, ok := cookie_session.Values["signed_in_userid"]; ok {
			fmt.Println("Logged via session...", val.(int64))
			return val.(int64)
		} else {
			return 0
		}
	}else if secure_cookie_store != nil {
		if cookie, err := r.Cookie(cook_auth_name); err == nil {
			value := make(map[string]string)
			if err = secure_cookie_store.Decode(cook_auth_name, cookie.Value, &value); err == nil {
				if val, ok := value["signed_in_userid"]; ok {
					fmt.Println("Logged via session...", val)
					if user_id, err :=strconv.ParseInt(val,10,64);err!=nil{
						panic(err)
					}else{
						return user_id
					}
				} else {
					return 0
				}
			}else{
				fmt.Errorf("%s\n", err.Error())
				return 0
			}
		}
	}else{
		panic(errors.New("Unable to find authenticated user due to uninitialised cookie store."))
	}
	return 0
}

const LoggedInUserContextKey = 321
const ApiKeyContextKey = 322
const ApiKeyOwner = 323


func MustBeUserAuthorised(r *http.Request, user_id int64) bool {
	if user := GetAuthorisedInUserObject(r); user != nil {
		if user_id != user.User_id {
			panic(NewHttpAPIErrorForbidden("Permission denied."))
			return false
		}
	}else{
		panic(NewHttpAPIErrorUnauthorised("No auth for request."))
		return false
	}
	return true
}

func MustBeAuthorised(r *http.Request) bool {
	if user := GetAuthorisedUserID(r); user == 0 {
		panic(NewHttpAPIErrorUnauthorised("No auth for request."))
		return false// Just in case later I want to remove panics (panics are stupid here)
	}
	return true
}

func MustBeUserAuthenticated(r *http.Request, user_id int64) bool {
	if auth_user_id := GetAuthenticatedUser(r); auth_user_id != 0 {
		if user_id != auth_user_id {
			panic(NewHttpAPIErrorForbidden("Permission denied."))
			return false
		}
	}else{
		panic(NewHttpAPIErrorUnauthorised("No auth for request."))
		return false
	}
	return true
}

func MustBeAuthenticated(r *http.Request) bool {
	if user_id := GetAuthenticatedUser(r); user_id == 0 {
		panic(NewHttpAPIErrorUnauthorised("No auth for request."))
		return false
	}
	return true
}

func MustNotBeAuthenticated(r *http.Request) bool {
	if user_id := GetAuthenticatedUser(r); user_id > 0 {
		panic(NewHttpAPIErrorUnauthorised("Already signed in."))
		return false
	}
	return true
}

func KeepUserInContext(r *http.Request, user  *User  ){
	context.Set(r, LoggedInUserContextKey, user)
}

func GetAuthorisedInUserObject(r *http.Request) *User {
	if rv := context.Get(r, ApiKeyOwner); rv != nil {
		Trace.Printf("Fetching auth user via api key: %v\n", rv)
		user := rv.(*User)
		return user
	} else if rv := context.Get(r, LoggedInUserContextKey); rv != nil {
		Trace.Printf("Fetching auth user via user id: %v\n", rv)
		user := rv.(*User)
		//if !user.Guest {
		//	panic(NewHttpAPIErrorUnauthorised("User id as a user id method can only be used for guest accounts."))
		//}
		return user
	}else if id := GetAuthenticatedUser(r);id>0{
		if user_object, present := GetUserByUserid(id);present{
			return user_object
		}
	}
	Trace.Println("No logged in user")
	return nil
}

func GetAuthorisedUserID(r *http.Request) int64 {
	if rv := context.Get(r, ApiKeyOwner); rv != nil {
		user := rv.(*User)
		return user.User_id
	} else if rv := context.Get(r, LoggedInUserContextKey); rv != nil {
		user := rv.(*User)
		//if !user.Guest {
		//	panic(NewHttpAPIErrorUnauthorised("User id as a user id method can only be used for guest accounts."))
		//}
		return user.User_id
	} else if id := GetAuthenticatedUser(r);id>0{
		return id
	}
	return 0
}

func MustNotHaveAnyApiOrUserIDHeaders(r *http.Request) {
	if rv := context.Get(r, ApiKeyOwner); rv != nil {
		panic(NewHttpAPIErrorBadRequest("Api key in header."))
	} else if rv := context.Get(r, LoggedInUserContextKey); rv != nil {
		panic(NewHttpAPIErrorBadRequest("User id in header."))
	}
}

func GetAuthorisedAPIUserObject(r *http.Request) *User {
	if rv := context.Get(r, ApiKeyOwner); rv != nil {
		Trace.Printf("Fetching auth user via api key: %v\n", rv)
		user := rv.(*User)
		return user
	}
	return nil
}

/**
 * Don't use this for checking if the user_id in the header belongs to an account that can be used for authenticating. If its not a guest account then it might have been turned into a full account.
 */
func GetAuthorisedGuestUserObject(r *http.Request) *User {
	if rv := context.Get(r, LoggedInUserContextKey); rv != nil {
		user := rv.(*User)
		return user
	}
	return nil
}

func RemoveAuthorisedGuestUserObject(r *http.Request) {
	if rv := context.Get(r, LoggedInUserContextKey); rv != nil {
		context.Delete(r,LoggedInUserContextKey)
	}
}


func SignUserIn(user_id int64, w http.ResponseWriter, r *http.Request) {
	// Get a session.
	Trace.Printf("Signing user in: %d\n", user_id)
	if cookie_store!= nil {
		cookie_session, _ := cookie_store.Get(r, cook_auth_name)
		// Get the previously flashes, if any.
		cookie_session.Values["signed_in_userid"] = int64(user_id)
		//	usernamen := MyCookieHandler(r)
		cookie_session.Save(r, w)
	} else if secure_cookie_store != nil {
		Trace.Println("Setting up secure cookie")
		value := map[string]string{
			"signed_in_userid": fmt.Sprintf("%d",user_id),
		}
		if encoded, err := secure_cookie_store.Encode(cook_auth_name, value); err == nil {
			cookie := &http.Cookie{
				Name:  cook_auth_name,
				Value: encoded,
				Secure: true,
				HttpOnly: true,
				Path:  "/",
			}
			Trace.Println("Secure cookie is set")
			http.SetCookie(w, cookie)
		}else{
			Trace.Println("Secure cookie is not set")
			panic(err)

		}
	}
}

func (guest_user *User) MakeNonguestAndDisableUser(gorm_db *gorm.DB) error {
	if err := gorm_db.Debug().Exec("UPDATE user SET enabled = 0, guest = 0 WHERE user_id = ?",guest_user.User_id).Error; err!=nil{
		return err
	}else{
		guest_user.Guest=false
		guest_user.Enabled=false
		return nil
	}
}

func (guest_user *User) MoveRecipesToUser(gorm_db *gorm.DB, new_user_id int64) error {
	if err := gorm_db.Debug().Exec("UPDATE recipe SET owner_id = ? WHERE owner_id = ?",new_user_id, guest_user.User_id).Error; err!=nil{
		return err
	}
	if err := gorm_db.Debug().Exec("UPDATE fav_recipe SET owner_id = ? WHERE owner_id = ?",new_user_id, guest_user.User_id).Error; err!=nil{
		return err
	}
	if err := gorm_db.Debug().Exec("UPDATE recipe_group SET owner_id = ? WHERE owner_id = ?",new_user_id, guest_user.User_id).Error; err!=nil{
		return err
	}
	if err := gorm_db.Debug().Exec("UPDATE recipe_rating SET owner_id = ? WHERE owner_id = ?",new_user_id, guest_user.User_id).Error; err!=nil {
		return err
	}
	return nil
}

func (guest_user *User) MakeNonguestUser(gorm_db *gorm.DB) error {
	if err := gorm_db.Debug().Exec("UPDATE user SET guest = 0 WHERE user_id = ?",guest_user.User_id).Error; err!=nil{
		return err
	}else{
		guest_user.Guest=false
		return nil
	}
}

func (guest_user *User) DisableUser(gorm_db *gorm.DB) error {
	if err := gorm_db.Debug().Exec("UPDATE user SET enabled = 0 WHERE user_id = ?",guest_user.User_id).Error; err!=nil{
		return err
	}else{
		guest_user.Enabled=false
		return nil
	}
}

func (p User) validate() (string, int) {
	if len(p.Email) == 0 {
		return "Missing email", 400
	}

	Re := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	if !Re.MatchString(p.Email) {
		return "Invalid email", 400
	}

	if len(p.Password) == 0 {
		return "Missing password", 400
	}
	if len(p.FirstName) == 0 {
		return "Missing first_name", 400
	}
	if len(p.LastName) == 0 {
		return "Missing last_name", 400
	}
	/*if len(p.Role) == 0 {
		return "Missing role", 400
	}
	if len(p.Gender) == 0 {
		return "Missing gener", 400
	}*/

	/*if len(p.FacebookUsername) == 0 {
		return "", 400

	}*/
	/*res, err := rethink.Db(DB).Table(USER_TABLE).Get(p.Id).Run(session)
	if res != nil {
		defer res.Close()
	}
	if err != nil {
		return err.Error(), 504
	} else if !res.IsNil() {
		return "The username is already in used", 400
	}*/
	return "", 200
}

type User struct {
	User_id     int64 `sql:"user_id" json:"user_id" gorm:"primary_key" sql:"AUTO_INCREMENT"`
	Email       string `json:"email" sql:"type:varchar(100);unique_index;default:null" `
	Created     int64 `json:"created" sql:"created"`
	Password    string `json:"password,omitempty" sql:"not null;"`
	FirstName   string `json:"first_name" sql:"type:varchar(100);not null;"`
	Source      string `json:"source" sql:"type:varchar(100);not null;"`
	LastName    string `json:"last_name" sql:"type:varchar(100);not null;"`
	Guest       bool `json:"guest" sql:"default:1" gorm:"column:guest"`
	Enabled     bool `json:"enabled" sql:"default:1" gorm:"column:enabled"`
	Facebook_id string `json:"facebook_id" sql:"null;default:null;type:varchar(100);unique_index"`
	LastLoggedIn int64 `json:"last_logged_in" sql:"last_logged_in"`
	Picture_url string `json:"picture_url" sql:"null;default:null;type:varchar(100);unique_index"`
	VerifyCode string `json:"verify_code" sql:"null;default:null;type:varchar(100);unique_index"`
	Handle string `json:"handle" sql:"null;default:null;type:varchar(100);unique_index"`
	AuthUserId string `json:"auth_user_id" sql:"null;default:null;type:varchar(100);auth_user_id"`
	ApiKey string `json:"api_key" sql:"null;default:null;type:varchar(150);index"`
}

func (p User) BcryptHashForPassword(password string) []byte {
	password_bytes := []byte(password)

	// Hashing the password with the default cost of 10
	// TODO Add Salt
	if hashedPassword, err := bcrypt.GenerateFromPassword(password_bytes, bcrypt.DefaultCost);err != nil {
		panic(err)
	}else {
		return hashedPassword
	}
}

func (p User) IsPasswordCorrect(password_attempt string) bool {
	if len(p.Password) == 0 {
		panic(errors.New("Don't compare empty passwords with bcrypt."))
	}
	// Hashing the password with the default cost of 10
	// TODO Add Salt
	err := bcrypt.CompareHashAndPassword([]byte(p.Password), []byte( password_attempt))
	return err==nil // nil means it's a match
}

type UserMeta struct {
	UserMetaID int64 `json:"user_meta_id"  gorm:"primary_key" sql:"AUTO_INCREMENT"`
	User_id     int64 `sql:"user_id;index;not_null" json:"user_id,omitempty"`
	MetaKey string  `json:"key" sql:"type:varchar(100);unique_index;not_null" gorm:"column:meta_key"`
	MetaValue string  `json:"value" sql:"not_null" gorm:"column:meta_value"`
	DeleteKey bool  `json:"delete_key,omitempty" sql:"-"`
}

func (UserMeta) TableName() string {
	return "usermeta"
}

type FacebookUser struct {
	Facebook_user_id int64 `json:"facebook_user_id"  gorm:"primary_key" sql:"AUTO_INCREMENT"`
	User_id     int64 `sql:"user_id;unique_index;not_null" json:"user_id" `
	Facebook_id string `json:"facebook_id" sql:"null;default:null;type:varchar(100);unique_index"`
}

type GoogleUser struct {
	Google_user_id int64 `json:"google_user_id"  gorm:"primary_key" sql:"AUTO_INCREMENT"`
	User_id     int64 `sql:"user_id;unique_index;not_null" json:"user_id" `
	Google_id string `json:"google_id" sql:"null;default:null;type:varchar(100);unique_index"`
}

type UserAdminAction struct {
	User_admin_id     int64 `sql:"user_admin_id" json:"user_admin_id" gorm:"primary_key" sql:"AUTO_INCREMENT"`
	User_id     int64 `sql:"user_id;unique_index;not_null" json:"user_id"`
	Created     int64 `json:"created" sql:"created"`
	RequiresPasswordReset bool `gorm:"column:reset_pass"`
	ResetLink string `json:"reset_code" sql:"type:varchar(100);unique_index;default:null" gorm:"column:reset_code"`
	PasswordResetMailSent int64 `gorm:"column:reset_sent"`
}

func (u UserAdminAction) GetEmail(gorm_db *gorm.DB) string {
	user := User{}
	if err := gorm_db.Debug().Where("user_id = ?", u.User_id).First(&user).Error; err != nil {
		// TODO Delay response
		if err != gorm.ErrRecordNotFound {
			panic(err)
		}
	}
	return user.Email
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func (u *UserAdminAction) ApplyNewPasswordResetLink(gorm_db *gorm.DB)  {
	link := randStringRunes(20)
	for {
		count := 0
		if e := gorm_db.Model(u).Where("reset_code = ?", link ).Count(&count).Error; e != nil {
			panic(e)
		}
		if count == 0 {
			break
		}

	}
	u.ResetLink = link
}

type SuggestUser struct {
	Handle    string `json:"handle"`
	Password  string `json:"password,omitempty" `
	FirstName string `json:"first_name"`
	Source    string `json:"source"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

func (p SuggestUser) ValidForGuestUserCreate() error {
	if len(p.Handle)==0{
		return errors.New("Missing handle")
	}
	if len(p.Source)==0{
		return errors.New("Invalid source")
	}
	return nil
}

var gorm_db *gorm.DB;
func AssignGormDBForUserAuth(new_gorm_db *gorm.DB)  {
	gorm_db = new_gorm_db
}

func (p SuggestUser) AssignValuesToUser(user *User) error {
	d:=map[string]interface{}{}
	user.Source = p.Source
	if len(user.Source)>0 {
		d["source"] = user.Source
	}
	user.Email = p.Email
	if len(user.Email)>0 {
		d["email"] = user.Email
	}
	user.FirstName = p.FirstName
	if len(user.FirstName)>0 {
		d["first_name"] = user.FirstName
	}
	user.LastName = p.LastName
	if len(user.LastName)>0 {
		d["last_name"] = user.LastName
	}
	if len(d)>0 {
		if gorm_db == nil {
			panic(errors.New("userauth needs a gorm_db instance defined."))
		}
		return gorm_db.Debug().Model(&user).Updates(d).Error
	}
	return nil
}

func (p PushToken) validate() (string, int) {
	if len(p.Token) == 0 {
		return "Missing token", 400
	}
	if p.User_id == 0 {
		return "Missing user id", 400 // Assigned from the cookie so no need to confirm that the user ID actually exists
	}
	if len(p.Device) == 0 {
		return "Missing device type", 400
	}
	if p.Device != "ios" {
		return "Invalid device type", 400
	}
	return "", 200
}

type PushToken struct {
	PushTokenID  int64 `gorm:"primary_key"`
	Token  string
	User_id   int64
	Device string
}

func makeTimestamp() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func GetSaltForVersion(version string) string {
	if version == "arse" {
		return "neversay"
	}
	return "neversay"
}

func VerifySHA256(version string, verify string, received_sha256 string) bool {
	salt := GetSaltForVersion(version)
	if len(salt) == 0 {
		panic("I need a version")
	}
	new_verify := salt + verify + salt
	h := sha256.New()
	io.WriteString(h, new_verify)
	Trace.Printf("I've been asked to verify: %s", received_sha256)

	Trace.Printf("%s", hex.EncodeToString(h.Sum(nil)))
	return hex.EncodeToString(h.Sum(nil)) == received_sha256
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
func RandSeqOfAlphaChars(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}


// @Title AccountInfo
// @Description The currently signed in user account info.
// @Accept  json
// @Success 200 {object}  simpleauthmysql.User The currently logged in user object.
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Not signed in.
// @Resource /account
// @Router /me          [get]
func MeHandler(w http.ResponseWriter, request *http.Request) {
	/*if logged_in_user_id := GetAuthenticatedUser(request);logged_in_user_id==0 {
		if logged_in_user_id := GetAuthorisedInUser(request);logged_in_user_id==0 {
			SendClientErrorUnauthorizedResult(w, request, "please signin.")
			return
		}
	}*/
	MustBeAuthorised(request)
	SendSignedInObject(w, request, false)
}

// @Title Suggest a guest ID for a new client
// @Description Request a user id for a client.
// @Param   suggested-user-info    body   simpleauthmysql.SuggestUser  true  "A valid push note token."
// @Success 200 {object}  simpleauthmysql.User The newly created user object.
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    "Not signed in."
// @Resource /request-guestid
// @Router /request-guestid          [post]
func SuggestGuestUserIDHandler(w http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	var t SuggestUser
	if err := decoder.Decode(&t); err == nil {
		if len(t.Handle)==0{
			t.Handle = RandSeqOfAlphaChars(50)
		}
		if validate_err := t.ValidForGuestUserCreate(); validate_err==nil {
			userIDFetcherChan <- t.Handle
			user := <-userFetcherChan

			if er:=t.AssignValuesToUser(user);er!=nil{
				panic(er)
			}else {
				if user.User_id > 0 {
					SendClientCreatedOKObject(w, request, user)
				}else {
					SendClientErrorUnauthorizedResult(w, request, "Not available")
				}
			}
		}else{
			SendClientErrorBadRequestError(w, request, validate_err)
		}
	}else{
		SendClientErrorBadRequestError(w, request, err)
	}
}

func RequestUserID( new_user_id string ) *User {
	if len(new_user_id)==0{
		new_user_id = RandSeqOfAlphaChars(50)
	}else if len(new_user_id) < MIN_GUEST_USERNAME_LENGTH {
		return nil
	}
	userIDFetcherChan <- new_user_id
	user := <-userFetcherChan
	return user
}

type FacebookSigninObject struct {
	Access_token string `json:"access_token"`
}

// @Title Facebook signup/signin
// @Description Using a valid Facebook access token, sign the user up (or in if the user is already signed up).
// @Accept  json
// @Param   access_token    body   simpleauthmysql.FacebookSigninObject     true        "A valid facebook access token which will be used to sign the user up."
// @Success 201 {object}  User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid or expired access_token
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Password doesn't meet the minimum complexity requirement.
// @Resource /account
// @Router /fb_signin          [post]
func SigninFacebookAccountHandler(w http.ResponseWriter, request *http.Request) {
	//MustNotBeAuthenticated(request)
	MustNotHaveAnyApiOrUserIDHeaders(request)

	decoder := json.NewDecoder(request.Body)

	var signin_object FacebookSigninObject
	if decodeerr := decoder.Decode(&signin_object); decodeerr!=nil {
		panic(decodeerr)
	}

	res, err := fb.Get("/me", fb.Params{
		"access_token": signin_object.Access_token,
		"fields":"name,email,first_name,last_name,id",
	})

	if err != nil {
		// err can be an facebook API error.
		// if so, the Error struct contains error details.
		SendClientErrorBadRequestError(w, request, err)
	} else {
		facebook_id := res["id"].(string)
		//
		// We've received a repsonse from Facebook, now see if an account already exists.
		if user, ok := GetUserByFacebookID(facebook_id); ok {
			SignUserIn(user.User_id, w, request)
			SendSignedInObject(w, request, false)
		} else {
			SendClientErrorBadRequestMessage(w, request, "Facebook account not found. Please signup first.")
		}

	}
}
type FacebookSignupObject struct {
	Access_token string `json:"access_token"`
	Password string `json:"password"`
}

// @Title SaveUserInfo
// @Description Save changes to the user object.
// @Accept  json
// @Param   access_token       body    simpleauthmysql.SuggestUser     true        "A user object containing the changes to be made."
// @Success 201 {object}  User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid or expired access_token
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Password doesn't meet the minimum complexity requirement.
// @Resource /user
// @Router /user/{user-id}      [put]
func SaveUser(w http.ResponseWriter, request *http.Request) {
	if user_id := GetAuthenticatedUser(request);user_id>0 {
		decoder := json.NewDecoder(request.Body)

		var change_user SuggestUser
		if decodeerr := decoder.Decode(&change_user); decodeerr != nil {
			panic(decodeerr)
		} else if len(change_user.Email) > 0 {
			SendClientErrorBadRequestMessage(w, request, "You can't change the email address of an account.")
			return
		} else if len(change_user.Source) > 0 {
			SendClientErrorBadRequestMessage(w, request, "Source can't be changed.")
			return
		} else if len(change_user.Handle) > 0 {
			SendClientErrorBadRequestMessage(w, request, "Handle can't be changed.")
			return
		} else if len(change_user.Password) > 0 {
			SendClientErrorBadRequestMessage(w, request, "Please use the reset password feature to change the password")
			return
		}else {
			if e:=gorm_db.Model(&User{}).Where("user_id = ?", user_id).Update(&change_user).Error; e != nil {
				SendClientErrorInternalServerErrorResult(w, request, gorm_db.Error)
			} else {
				SendSignedInObject(w, request, true)
			}
		}
	}
}

// @Title GetUserMetaInfo
// @Description Fetch a user's meta fields.
// @Accept  json
// @Param   fields       path    string     true        "A comma deliminated list of meta keys"
// @Success 200 {array}  UserMeta
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid or expired access_token
// @Resource /user
// @Router /user_meta/{fields}      [put]
func GetUserMeta(w http.ResponseWriter, request *http.Request) {
	if user_id := GetAuthenticatedUser(request);user_id>0 {
		if fields_s,present := MightHaveGetString(request,"fields");present {
			fields_test := strings.Split(fields_s, ",")
			fields := make([]string, 0)
			for _, field := range fields_test {
				if len(field) == 0 {
					SendClientErrorBadRequestMessage(w, request, "Illegal empty field value.")
					return
				}
				fields = append(fields, field)
			}

			present_meta:=make([]*UserMeta,0)
			if err := gorm_db.Debug().Where("user_id = ? AND meta_key IN (?)", user_id, fields).Find(&present_meta).Error; err != nil {
				// TODO Delay response
				if err != gorm.ErrRecordNotFound {
					panic(err)
				}
			}
			for _,meta:=range present_meta{
				meta.User_id=0
			}
			SendClientOKObject(w,request,present_meta)
		}else{
			present_meta:=make([]*UserMeta,0)
			if err := gorm_db.Debug().Where("user_id = ?", user_id).Find(&present_meta).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					panic(err)
				}
			}
			for _,meta:=range present_meta{
				meta.User_id=0
			}
			SendClientOKObject(w,request,present_meta)
		}
	}
}

// @Title SaveUserMetaInfo
// @Description Save changes to the user object.
// @Accept  json
// @Param   body       body    simpleauthmysql.UserMeta     true        "A user object containing the changes to be made."
// @Success 201 {object}  User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid or expired access_token
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Password doesn't meet the minimum complexity requirement.
// @Resource /user
// @Router /user_meta/{user-id}      [put]
func SaveUserMeta(w http.ResponseWriter, request *http.Request) {
	if user_id := GetAuthenticatedUser(request);user_id>0 {
		decoder := json.NewDecoder(request.Body)

		var user_meta []UserMeta
		if decodeerr := decoder.Decode(&user_meta); decodeerr != nil {
			panic(decodeerr)
		} else if len(user_meta) == 0 {
			SendClientErrorBadRequestMessage(w, request, "No data received.")
			return
		}else {
			seend_keys:=make(map[string]bool,0)
			for _,meta:= range user_meta{
				if len(meta.MetaKey)==0{
					SendClientErrorBadRequestMessage(w, request, "User meta key is missing.")
					return
				}else if meta.User_id>0 {
					SendClientErrorBadRequestMessage(w, request, "Don't set the user_id field.")
					return
				} else if _, present:=seend_keys[meta.MetaKey];present {
					SendClientErrorBadRequestMessage(w, request, "Duplicate meta key.")
					return
				}
				seend_keys[meta.MetaKey]=true
			}
			db:=gorm_db.Begin()
			for _,meta:= range user_meta {
				if meta.DeleteKey{
					if e:=db.Raw("DELETE FROM user_meta WHERE user_id = ? AND meta_key = ?", user_id, meta.MetaKey).Error;e!=nil{
						db.Rollback()
						panic(e)
					}
				}else{
					count:=0
					user_meta_in_db:=UserMeta{}
					if e:=db.Model(&UserMeta{}).Where("user_id = ? AND meta_key = ?", user_id, meta.MetaKey).Find(&user_meta_in_db).Count(&count).Error;e!=nil{
						if e != gorm.ErrRecordNotFound {
							db.Rollback()
							panic(e)
						}
					}
					if count>0{
						user_meta_in_db.MetaValue = meta.MetaValue
						if e:=db.Model(&UserMeta{}).Update(&user_meta_in_db).Error;e!=nil{
							db.Rollback()
							panic(e)
						}
					}else{
						meta.User_id = user_id
						if e:=db.Model(&UserMeta{}).Create(&meta).Error;e!=nil{
							db.Rollback()
							panic(e)
						}
					}

				}
			}
			if e:=db.Commit().Error;e!=nil{
				panic(e)
			}
			SendClientCreatedOKResult(w,request,"All meta saved.")

		}
	}
}

// @Title SaveUser
// @Description Using a valid Facebook access token, sign the user up (or in if the user is already signed up).
// @Accept  json
// @Param   access_token       body    simpleauthmysql.FacebookSignupObject     true        "A valid facebook access token which will be used to sign the user up."
// @Success 201 {object}  User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid or expired access_token
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Password doesn't meet the minimum complexity requirement.
// @Resource /account
// @Router /fb_signup          [post]
func CreateOrSigninFacebookAccountHandler(w http.ResponseWriter, request *http.Request) {
	//MustNotBeAuthenticated(request)
	GetAuthenticatedUser(request)

	//type FacebookSign struct {
	//}
	//
	// Process the path variables
	decoder := json.NewDecoder(request.Body)

	var signin_object FacebookSignupObject
	if decodeerr := decoder.Decode(&signin_object); decodeerr!=nil {
		panic(decodeerr)
	}
	if len(signin_object.Access_token)==0{
		SendClientErrorBadRequestError(w, request, errors.New("Missing access_token."))
		return
	}
	res, err := fb.Get("/me", fb.Params{
		"access_token": signin_object.Access_token,
		"fields":"name,email,first_name,last_name,id",
	})

	if err != nil {
		// err can be an facebook API error.
		// if so, the Error struct contains error details.
		SendClientErrorBadRequestError(w, request, err)
	} else {
		var email string
		facebook_id := res["id"].(string)
		//
		// We've received a repsonse from Facebook, now see if an account already exists.
		if user, ok := GetUserByFacebookID(facebook_id); ok {
			SignUserIn(user.User_id, w, request)
			SendSignedInObject(w, request, false)
		} else {
			//
			// Proceed to create the account with the FB details

			// First, I need a password for the account.
			//if len(signin_object.Password) == 0 {
			//	SendClientErrorResultExtra(w,request, http.StatusBadRequest,"Missing password. I a need password when creating a new user.", res )
			//	return
			//} else
			if len(signin_object.Password) > 0 && len(signin_object.Password) <= 5 {
				SendClientErrorBadRequestMessage(w, request, "Password must be at least 6 characters long")
				return
			} else if val, ok := res["email"]; ok {
				email = val.(string)
			} else {
				email = fmt.Sprintf("%s@top10anything.com", facebook_id)
				//Error.Printf("%v\n", res)
				//panic(errors.New("Facebook returned a response that didn't include a useable email")) //TODO Do somethin more sensible here like insist the client sends a username or email
			}

			if DoesUsernameExist(email) {
				SendClientErrorNotAcceptableResultExtra(w, request, "Username is already taken.", map[string]interface{}{"email": email})
			} else {
				// TODO: Any of these could be nil and that'll panic
				// TODO Password hard coded >O_o<
				first_name :=res["first_name"].(string)
				last_name := res["last_name"].(string)
				//email:=""
				//if email_original,ok :=res["email"];ok {
				//	email = email_original.(string)
				//}
				new_user := User{Source:"facebook", Password: signin_object.Password, FirstName:first_name,LastName: last_name, Email:email, Facebook_id:facebook_id,Created:time.Now().Unix(),Picture_url:"https://graph.facebook.com/v2.6/" + facebook_id + "/picture"}
				if gorm_db.Create(&new_user).Error != nil {
					SendClientErrorInternalServerErrorResult(w, request,gorm_db.Error)
				} else {
					SignUserIn(new_user.User_id, w, request)
					SendSignedInObject(w, request, true)
				}
			}
		}
	}

	// read my last feed.
	Trace.Println("my latest feed story is:", res.Get("data.0.story"))
}

func EnforceSignedInHandler(w http.ResponseWriter, request *http.Request) bool {
	user_id := GetAuthenticatedUser(request)

	if user_id == 0 {
		SendClientErrorUnauthorizedResult(w, request, "Please signin")
		return false
	} else {
		return true
	}

}

func GetUserByUserid(user_id int64) (*User, bool) {
	var user User
	if err:=gorm_db.Where(User{User_id: user_id}).First(&user).Error;err!=nil{
		if err!=gorm.ErrRecordNotFound{
			panic(err)
		}
	}
	return &user, user.User_id>0
}

func GetUserByUsername(username string) (*User, bool) {
	var user User
	gorm_db.Where(User{Email: username}).First(&user)
	return &user, user.User_id>0
}

func GetUserByEmail(email string) (*User, bool) {
	var user User
	gorm_db.Where(User{Email: email}).First(&user)
	return &user, user.User_id>0
}

func DoesUsernameExist(username string) bool {
	var user User
	gorm_db.Where(User{Email: username}).First(&user)
	return user.User_id > 0
}

func CreateUser(new_user *User) error {
	return gorm_db.Create(&new_user).Error
}

func DoesFacebookIDAlreadyExist(facebook_id string) bool {
	var user User
	gorm_db.Where(User{Facebook_id: facebook_id}).First(&user)
	return user.User_id>0
}

func GetUserByFacebookID(facebook_id string) (*User,bool) {
	var user User
	gorm_db.Where(User{Facebook_id: facebook_id}).First(&user)
	return &user, user.User_id>0
}

type prepLoggedInUserResponseType func(logged_in_user *User) (interface{})

var prepLoggedInResponse prepLoggedInUserResponseType
func PrepLoggedInUserResponseHandler( h prepLoggedInUserResponseType  ){
	prepLoggedInResponse = h
}

func SendSignedInObject(w http.ResponseWriter, request *http.Request, created bool) {
	userid:= GetAuthenticatedUser(request)
	if userid==0 {
		userid = GetAuthorisedUserID(request)
	}
	if userid == 0 {
		panic(NewHttpAPIErrorUnauthorised("There's no one logged in"))
	}
	p, present := GetUserByUserid(userid)
	if present == false {
		panic(NewHttpAPIInternalErrorMessage("Request to send user object that doesn't exist"))
	}

	response := prepLoggedInResponse(p)

	json_body, json_err := json.Marshal(response)
	if json_err != nil {
		SendClientErrorInternalServerErrorResult(w, request, fmt.Errorf("Error reading content on the server."))
	} else {
		if created {
			SendClientCreatedJsonStringResult(w, request, string(json_body))
		} else {
			SendClientOKJsonResult(w, request, string(json_body))
		}
	}
}

type SigninObject struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// @Title AccountSignin
// @Description Sign a user in to your app.
// @Accept  json
// @Param   username    body   simpleauthmysql.SigninObject  true  "The username, must be unique and the password for the account."
// @Success 200 {object}  User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Credentials are incorrect.
// @Resource /account
// @Router /signin          [post]
func SigninToAccountHandler(w http.ResponseWriter, request *http.Request) {
	//	MustNotBeAuthenticated(request)
	MustNotHaveAnyApiOrUserIDHeaders(request)

	decoder := json.NewDecoder(request.Body)

	var signin_object SigninObject
	if decodeerr := decoder.Decode(&signin_object); decodeerr != nil {
		panic(decodeerr)
	}

	if len(signin_object.Password) == 0 {
		panic(NewHttpAPIErrorBadRequest("Missing password"))
	}

	//if len(signin_object.Username) > 0 {
	//	AuthenticateUserInWithUsernameAndPassword(w, request ,signin_object.Username,signin_object.Password);
	//} else
	if len(signin_object.Email)>0 {
		AuthenticateUserInWithEmailAndPassword(w, request ,signin_object.Email,signin_object.Password);
	} else {
		panic(NewHttpAPIErrorBadRequest("Missing username"))
	}
}

//func AuthenticateUserInWithUsernameAndPassword(w http.ResponseWriter, request *http.Request,username string, password string) bool {
//	var user User
//	if len( username ) == 0 {
//		panic(errors.New("Missing username"));
//	}
//	if len( password ) == 0 {
//		panic(errors.New("Missing password"));
//	}
//	if err:=gorm_db.Debug().Where(&User{Email: username ,Password:password}).First(&user).Error;err!=nil{
//		if err!=gorm.ErrRecordNotFound {
//			panic(err)
//		}
//	}
//
//	if user.User_id == 0 {
//		SendClientErrorUnauthorizedResult(w, request, "Incorrect credentials")
//		return false
//	} else {
//		SignUserIn(user.User_id, w, request)
//		SendSignedInObject(w, request, false)
//		return true
//	}
//}

func AuthenticateUserInWithEmailAndPassword(w http.ResponseWriter, request *http.Request, email string, password string) bool {
	var user User
	if len(email) == 0 {
		panic(errors.New("Missing email"));
	}
	if len( password ) == 0 {
		panic(errors.New("Missing password"));
	}
	if err:=gorm_db.Debug().Where(&User{Email: email,Password:password}).First(&user).Error;err!=nil{
		if err!=gorm.ErrRecordNotFound {
			panic(err)
		}
	}
	if user.User_id == 0 {
		SendClientErrorUnauthorizedResult(w, request, "Incorrect credentials")
		return false
	} else {
		SignUserIn(user.User_id, w, request)
		SendSignedInObject(w, request, false)
		return true
	}
}

type NewPushNoteObject struct {
	Token string `json:"token"`
	Device string `json:"device"`
}


// @Title AddPushNoteToAccount
// @Description Sign a user up to your app.
// @Accept  json
// @Param   token    body   simpleauthmysql.NewPushNoteObject  true  "A valid push note token along with the platform the push token is for (ios/android/chrome/safari)."
// @Success 201 {object}  int   If the token was successfully added
// @Success 200 {object}  int   If the token is already assigned.
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid token
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Invalid device type
// @Resource /account
// @Router /updatenote          [post]
func AddPushNoteToAccountHandler(w http.ResponseWriter, request *http.Request) {
	if EnforceSignedInHandler(w, request) == false {
		return
	}
	user_id := GetAuthenticatedUser(request)

	var logged_in_user *User
	if user_id>0 {
		logged_in_user,_ = GetUserByUserid(user_id)
	}else{
		logged_in_user = nil
	}

	decoder := json.NewDecoder(request.Body)

	var new_push_object NewPushNoteObject
	decodeerr := decoder.Decode(&new_push_object)
	if decodeerr != nil {
		panic(decodeerr)
	}
	Trace.Printf("Adding token: %v\n", new_push_object)

	if len(new_push_object.Token) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing token")
	} else if len(new_push_object.Device) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing device type")
	} else {
		var push_token PushToken
		gorm_db.Where(PushToken{Token:new_push_object.Token}).First(&push_token)

		if push_token.PushTokenID == 0 {
			push_token.Device="ios"
			if rv := context.Get(request, LoggedInUserContextKey); rv != nil {
				user := rv.(*User)
				push_token.User_id = user.User_id

				gorm_db.Save(&push_token)

				SendClientCreatedOKResult(w, request, "Push received")
			}else{
				SendClientErrorInternalServerErrorResult(w,request,errors.New("Unknown error while fetching contect parameter"))
				return
			}
		} else {
			// TODO Check if rthe username is different befor doing this
			push_token.Device="ios"
			push_token.User_id = logged_in_user.User_id
			SendClientCreatedOKObject(w,request,push_token)
		}
	}
}

// @Title AccountSignUp
// @Description Sign a user up to your app.
// @Accept  json
// @Param   user    body   simpleauthmysql.User  true  "The username, must be unique."
// @Success 201 {object}  simpleauthmysql.User
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Non unique username
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Non unique email (already signed up)
// @Failure 400 {object}  simpleauthmysql.HttpAPIError    Password doesn't meet the minimum complexity requirement.
// @Resource /account
// @Router /signup          [post]
func SignupToAccountHandler(w http.ResponseWriter, request *http.Request) {
	MustNotBeAuthenticated(request)
	decoder := json.NewDecoder(request.Body)

	var signup_object User
	decodeerr := decoder.Decode(&signup_object)
	if decodeerr != nil {
		panic(decodeerr)
	}

	/*if len(signup_object.Id) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing username")
	} else */
	message,error_code:=signup_object.validate()
	if len(message)>0 && error_code==400 {
		SendClientErrorBadRequestMessage(w, request, message)
	} else {
		var user_existing User
		if err:=gorm_db.Where(User{Email:signup_object.Email}).Find(&user_existing).Error;err!=nil{
			if err != gorm.ErrRecordNotFound {
				panic(err)
			}
		}
		if user_existing.User_id==0 {
			if err:=gorm_db.Where(User{Email:signup_object.Email}).Find(&user_existing).Error;err!=nil{
				if err != gorm.ErrRecordNotFound {
					panic(err)
				}
			}
		}else{
			SendClientErrorBadRequestMessage(w, request, "Username is already taken.")
			return
		}
		if user_existing.User_id==0 {
			guest_user := GetAuthorisedGuestUserObject(request)
			if guest_user != nil {
				Trace.Printf("Replacing guest user account: %d\n", guest_user.User_id)
				RemoveAuthorisedGuestUserObject(request)
				if error := gorm_db.Debug().Exec("UPDATE user SET enabled = 0, guest = 0 WHERE user_id = ?",guest_user.User_id).Error; error != nil {
					panic(error)
				}
				Trace.Printf("Old guest account : %v\n", guest_user)
			}

			signup_object.Enabled = true
			signup_object.Guest = true // Can't be a guest any longer!
			if error := gorm_db.Create(&signup_object).Error; error != nil {
				SendClientErrorInternalServerErrorResult(w, request, error)
			} else {
				// TODO I need to do this because of a bug where guest wont be included in the `insert into`....
				if err:=signup_object.MakeNonguestUser(gorm_db);err!=nil{
					panic(err)
				}
				if guest_user != nil {
					if err := guest_user.MoveRecipesToUser(gorm_db, signup_object.User_id); err != nil {
						panic(err)
					}
				}
				signup_object.Password=""
				SendClientCreatedOKObject(w, request, signup_object)
			}
		} else {
			SendClientErrorBadRequestMessage(w, request, "Email is already in use.")
		}
	}
}

func SignOutOfAccountHandler(w http.ResponseWriter, req *http.Request) {
	MustNotHaveAnyApiOrUserIDHeaders(req)

	if rv := context.Get(req, LoggedInUserContextKey); rv != nil {
		context.Clear(req)
	}
	if cookie_store!=nil {
		session, _ := cookie_store.Get(req, cook_auth_name)
		session.Values["signed_in_userid"] = int64(0)
		_ = session.Save(req, w)
	}else if secure_cookie_store != nil {
		value := map[string]string{
			"signed_in_userid": "0",
		}
		if encoded, err := secure_cookie_store.Encode(cook_auth_name, value); err == nil {
			cookie := &http.Cookie{
				Name:  cook_auth_name,
				Value: encoded,
				Secure: true,
				HttpOnly: true,
				Path:  "/",
			}
			http.SetCookie(w, cookie)
		}
	}
	SendClientOKMessageResult(w, req, "Signed out.")
}

func SignUserOut(w http.ResponseWriter, req *http.Request) {
	if rv := context.Get(req, LoggedInUserContextKey); rv != nil {
		context.Clear(req)
	} else if rv := context.Get(req, ApiKeyContextKey); rv != nil {
		context.Clear(req)
	}
	if cookie_store!=nil {
		session, _ := cookie_store.Get(req, cook_auth_name)
		session.Values["signed_in_userid"] = int64(0)

		_ = session.Save(req, w)
	}else if secure_cookie_store != nil {
		value := map[string]string{
			"signed_in_userid": "0",
		}
		if encoded, err := secure_cookie_store.Encode(cook_auth_name, value); err == nil {
			cookie := &http.Cookie{
				Name:  cook_auth_name,
				Value: encoded,
				Path:  "/",
				Secure: true,
				HttpOnly: true,
			}
			http.SetCookie(w, cookie)
		}
	}
}

func NotAllowedHandler(w http.ResponseWriter, request *http.Request) {
	SendClientErrorNotAcceptableResult(w, request, "Not Allowed")
}

/*type isRequestExemptFromApiHeadersAction func(r *http.Request) bool

var isRequestExemptFromApiHeaders isRequestExemptFromApiHeadersAction
func AttachExemptFromApiHeadersAction( h isRequestExemptFromApiHeadersAction ){
	isRequestExemptFromApiHeaders = h
}*/
func ProcessHeaderUserIdKey(w http.ResponseWriter, r *http.Request) ( requires_further_processing bool , go_to_next bool ){
	if user_id := r.Header.Get("Userid"); len(user_id) > 0 {
		Trace.Printf("User ID in header is: %s\n", user_id)
		user := &User{}
		if err := gorm_db.Where("handle = ?", user_id).First(user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				if user = RequestUserID(user_id); user == nil {
					Trace.Println("No user with ID so creating: " + user_id)
				}
			} else {
				panic(err)
			}
		}
		if user == nil || user.User_id == 0 {
			SendClientErrorUnauthorizedResult(w, r, "Invalid user_id")
			return false, false
		}
		go NotifyApiCall(user.User_id, r.URL.Path)
		context.Set(r, LoggedInUserContextKey, user)
		return false, true
	}
	return true, false
}

func ProcessHeaderApiKey(w http.ResponseWriter, r *http.Request) ( requires_further_processing bool , go_to_next bool ){
	if api_key := r.Header.Get("Apikey"); len(api_key) > 0 {
		if already_set_api_key := context.Get(r, ApiKeyContextKey); already_set_api_key != nil {
			if already_set_api_key == api_key {
				return false, true
			} else {
				SignUserOut(w, r)
			}
		}
		api_key_object := ApiKey{}
		if gorm_db==nil{
			panic(errors.New("Setup a DB first."))
		}
		if get_api_key_error := gorm_db.Debug().Where("api_key = ?", api_key).First(&api_key_object).Error; get_api_key_error != nil {
			if get_api_key_error==gorm.ErrRecordNotFound{
				SendClientErrorUnauthorizedResult(w, r, "Invalid key")
				return false, false

			}else {
				panic(get_api_key_error)
			}
		}

		if api_key_object.Api_key_id > 0 {
			if api_key_object.Valid && api_key_object.Expires > time.Now().Unix() {
				api_key_owner := User{}
				err := gorm_db.Where("user_id = ?", api_key_object.Owner_id).First(&api_key_owner).Error

				if err != nil {
					panic(err)
				}

				if api_key_owner.User_id == 0 {
					panic(NewHttpAPIInternalErrorMessage("Failed to load user from api key owner"))
				}

				if api_key_owner.User_id > 0 {
					go NotifyApiCall(api_key_object.Owner_id, r.URL.Path)

					context.Set(r, ApiKeyContextKey, api_key_object)
					context.Set(r, ApiKeyOwner, &api_key_owner)
					SignUserIn(api_key_object.Owner_id, w, r)

					return false, true
				} else {
					panic(NewHttpAPIInternalErrorMessage("Missing owner"))
				}
			} else {
				//Trace.Printf("Expired %d - %d =  %d\n", api_key_object.Expires, time.Now().Unix(), (api_key_object.Expires > time.Now().Unix()))
				// TODO Delay this connection response for security reasons.
				SendClientErrorUnauthorizedResult(w, r, "Expired key")
				return false, false
			}
		} else {
			// TODO Delay this connection response for security reasons.
			SendClientErrorUnauthorizedResult(w, r, "Missing key")
			return false, false
		}
	}
	return true, false
}

func EnforceRecipeAPIHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
		}else if requires_further_processing, go_to_next := ProcessHeaderApiKey(w,r);!requires_further_processing  {
			if go_to_next {
				h.ServeHTTP(w, r)
			}
		}else if requires_further_processing, go_to_next := ProcessHeaderUserIdKey(w,r);!requires_further_processing  {
			if go_to_next {
				h.ServeHTTP(w, r)
			}
		}else{
			h.ServeHTTP(w, r)
		}
	})
}

func NotifyApiCall( user_id int64, api_call string ){
	type ApiAll struct {
		Call_url   string `db:"call_url"`
		User_id    int64 `db:"user_id"`
		Cost       int `db:"cost"`
		Api_key_id int64 `db:"api_key_id"`
	}
	c := ApiAll{Call_url:api_call,User_id:user_id,Cost:1,Api_key_id:1}
	err := gorm_db.Raw("INSERT INTO api_call (user_id,call_url,cost,api_key_id) VALUES (?,?,?,?)", c.User_id,c.Call_url,c.Cost,c.Api_key_id).Error
	if err != nil {
		log.Fatal(err)
	}
}

func CanHaveGetInt(w http.ResponseWriter, r *http.Request, param string) (int, bool, bool) {
	menu_item_id_s := r.URL.Query().Get(param)
	if len(menu_item_id_s) == 0 {
		return 0, false, true
	}else {
		group_id, group_conv_err := strconv.Atoi(menu_item_id_s)
		if group_conv_err != nil {
			SendClientErrorBadRequestMessage(w, r, "Illegal " + param)
			return 0, true, false
		}
		return group_id, true, true
	}
}

func MustHaveGetInt(w http.ResponseWriter, r *http.Request, param string) (int64, bool) {
	menu_item_id_s := r.URL.Query().Get(param)
	fmt.Println("a:",menu_item_id_s)
	if len(menu_item_id_s)==0 {
		menu_item_id_s = r.URL.Query().Get(":"+param)
	}
	if len(menu_item_id_s) == 0 {
		SendClientErrorBadRequestMessage(w, r, "Missing " + param)
		return 0, false
	}else {
		group_id, group_conv_err := strconv.ParseInt(menu_item_id_s,10,0)
		if group_conv_err != nil {
			SendClientErrorBadRequestMessage(w, r, "Illegal " + param)
			return 0, false
		} else if group_id == 0 {
			SendClientErrorBadRequestMessage(w, r, "Illegal " + param)
			return 0, false
		}
		return group_id, true
	}
}

func MightHaveGetInt(r *http.Request, param string) (int64, bool, error) {
	menu_item_id_s := r.URL.Query().Get(param)

	if len(menu_item_id_s)==0 {
		menu_item_id_s = r.URL.Query().Get(":"+param)
	}
	if len(menu_item_id_s) == 0 {
		return 0, false, nil
	}else {
		group_id, group_conv_err := strconv.ParseInt(menu_item_id_s,10,0)
		if group_conv_err != nil {
			return 0, true, NewHttpAPIErrorBadRequest("Illegal " + param)
		}
		return group_id, true, nil
	}
}

func MustHaveGetString(w http.ResponseWriter, r *http.Request, param string) (string, bool) {
	menu_item_id_s := r.URL.Query().Get(param)
	if len(menu_item_id_s) == 0 {
		menu_item_id_s = r.URL.Query().Get(":" + param)
		if len(menu_item_id_s) == 0 {
			SendClientErrorBadRequestMessage(w, r, "Missing " + param)
			return "", false
		}
	}
	return menu_item_id_s, true
}

func MightHaveGetString(r *http.Request, param string) (string, bool) {
	menu_item_id_s := r.URL.Query().Get(param)

	if len(menu_item_id_s)==0 {
		menu_item_id_s = r.URL.Query().Get(":"+param)
	}
	if len(menu_item_id_s) == 0 {
		return "", false
	}else {
		return menu_item_id_s, true
	}
}
