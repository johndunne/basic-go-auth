package simpleauthmysql

import (
	"encoding/json"
	"io/ioutil"
	"fmt"
	"io"
	"net/http"
	"log"
	"os"
	"runtime/debug"
)

const (
	DB               = "test"
	PUSH_TOKEN_TABLE = "push_token"
	USER_TABLE       = "user"
)

var (
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger
)
const GuestApiKey = "guest_api_key"
const GuestMaxNumMonthlyCalls = 50000

func initLog( traceHandle io.Writer, infoHandle io.Writer, warningHandle io.Writer, errorHandle io.Writer) {

	Trace = log.New(traceHandle,
		"TRACE: ",
		log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate | log.Ltime | log.Lshortfile)

	Warning = log.New(warningHandle,
		"WARNING: ",
		log.Ldate | log.Ltime | log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate | log.Ltime | log.Lshortfile)
}

func init() {
	initLog(os.Stdout, os.Stdout, os.Stdout, os.Stderr)
}

func SendClientCreatedOKResult(w http.ResponseWriter, request *http.Request, message string) {
	SendClientCreatedJsonStringResult(w, request, fmt.Sprintf("{\"message\":\"%s\"}", message))
}

func SendClientCreatedOKObject(w http.ResponseWriter, request *http.Request, obj interface{}) {
	response, err := json.Marshal(obj)
	if err != nil {
		SendClientErrorInternalServerErrorResult(w, request, err)
	} else {
		SendClientCreatedJsonStringResult(w, request, string(response))
	}
}

func SendEmptyClientOKObject(w http.ResponseWriter, request *http.Request) {
	SendClientOKObject(w, request, map[string]string{})
}

func SendEmptyClientOKArray(w http.ResponseWriter, request *http.Request) {
	SendClientOKObject(w, request, []string{})
}

func SendClientOKObject(w http.ResponseWriter, request *http.Request, obj interface{}) {
	response, err := json.MarshalIndent(obj,"","   ")
	if err != nil {
		SendClientErrorInternalServerErrorResult(w, request, err)
	} else {
		SendClientOKJsonResult(w, request, string(response))
	}
}

func SendClientCustomCodeObject(w http.ResponseWriter, request *http.Request, error_code int, obj interface{}) {
	response, err := json.MarshalIndent(obj,"","   ")
	if err != nil {
		SendClientErrorInternalServerErrorResult(w, request, err)
	} else {
		w.WriteHeader(error_code)
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}
}

func SendClientCreatedJsonStringResult(w http.ResponseWriter, request *http.Request, message string) {
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, message)
}

func SendClientNoContentResult(w http.ResponseWriter, request *http.Request, message string) {
	w.WriteHeader(http.StatusNoContent)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, message)
}

func SendClientOKJsonResult(w http.ResponseWriter, request *http.Request, message string) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, message)
}

func SendClientOKMessageResult(w http.ResponseWriter, request *http.Request, message string) {
	SendClientOKObject(w, request, map[string]string{"response":"ok","message":message})
}

func SendClientErrorBadRequestError(w http.ResponseWriter, request *http.Request, error error) {
	Info.Println("BAD Request:[" + request.Method + "]{" + request.URL.Path + "}?" + request.URL.RawQuery )
	SendClientErrorResult(w, request, http.StatusBadRequest, error.Error())
}

func SendClientErrorBadRequestMessage(w http.ResponseWriter, request *http.Request, message string) {
	SendClientErrorResult(w, request, http.StatusBadRequest, message)
}

func SendClientErrorUnauthorizedResult(w http.ResponseWriter, request *http.Request, error_message string) {
	SendClientErrorResult(w, request, http.StatusUnauthorized, error_message)
}

func SendClientErrorForbiddenResult(w http.ResponseWriter, request *http.Request) {
	sendClientErrorEmptyBodyResult(w, request, http.StatusForbidden)
}
func SendClientErrorNotAcceptableResult(w http.ResponseWriter, request *http.Request, error_message string) {
	SendClientErrorResult(w, request, http.StatusNotAcceptable, error_message)
}

func SendClientErrorNotAcceptableResultExtra(w http.ResponseWriter, request *http.Request, error_message string, extra map[string]interface{}) {
	SendClientErrorResultExtra(w, request, http.StatusNotAcceptable, error_message, extra)
}

func SendClientErrorNotFoundResult(w http.ResponseWriter, request *http.Request, message string) {
	SendClientErrorResult(w, request, http.StatusNotFound, message)
}

func SendClientErrorMethodNotAllowedResult(w http.ResponseWriter, request *http.Request) {
	sendClientErrorEmptyBodyResult(w, request, http.StatusMethodNotAllowed)
}

// An unexpceted error
func SendClientErrorInternalServerErrorResult(w http.ResponseWriter, request *http.Request, error_message error) {
	//err := errors.Wrap(error_message, 1)
	//log.Println("Unexpected Error: Request:[" + request.Method + "]{" + request.URL.Path + "}?" + request.URL.RawQuery )
	//log.Println(err.ErrorStack())
	SendClientErrorResult(w, request, http.StatusInternalServerError, error_message.Error())
}

func sendClientErrorEmptyBodyResult(w http.ResponseWriter, request *http.Request, http_code int) {
	Info.Printf("ERROR EMPTY BODY RESONSE: %d\n", http_code)
	w.WriteHeader(http_code)
	w.Header().Set("Content-Type", "application/json")
}

func SendClientError(w http.ResponseWriter, request *http.Request, validate_error error) {
	SendClientErrorResult(w,request,validate_error.(*HttpAPIError).ErrorCode, validate_error.(*HttpAPIError).ErrorMessage)
}

func SendClientErrorResult(w http.ResponseWriter, request *http.Request, http_code int, error_message string) {
	w.WriteHeader(http_code)
	//if http_code == http.StatusInternalServerError {
		debug.PrintStack()
	//}
	Info.Printf("Client ERROR: %s\n", error_message)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{\"error\":\""+error_message+"\"}")
}

func SendClientGenericResponse(w http.ResponseWriter, request *http.Request, http_code int) {
	w.WriteHeader(http_code)
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, "{\"error\":\""+http.StatusText(http_code)+"\"}")
}

func SendClientErrorResultExtra(w http.ResponseWriter, request *http.Request, http_code int, error_message string, extra map[string]interface{} ) {
	debug.PrintStack()
	Error.Printf("ERROR: %s\n", error_message)
	w.WriteHeader(http_code)
	w.Header().Set("Content-Type", "application/json")
	extra["error"] = error_message

	response, new_object_err := json.Marshal(extra)
	if new_object_err != nil {
		SendClientErrorInternalServerErrorResult(w, request, new_object_err)
	} else {
		io.WriteString(w, string(response))
	}

}

/*func MeHandler(w http.ResponseWriter, request *http.Request) {
	logged_in := MyCookieHandler(w, request)

	Trace.Printf("Me Says: %s\n", logged_in)
	if len(logged_in) == 0 {
		SendClientErrorUnauthorizedResult(w, request, "please signin.")
	} else {
		SendSignedInObject(w, request, false)
	}
}*/

type ObjectHandler struct {
	ObjectCreationHandler func(string, *json.Decoder, http.ResponseWriter, *http.Request) (string, interface{})
}

var objectHandler ObjectHandler

func SetDefaultObjectCreationHandler(f func(string, *json.Decoder, http.ResponseWriter, *http.Request) (string, interface{})) {
	objectHandler = ObjectHandler{f}
}

/*func CreateObjectHandler(w http.ResponseWriter, request *http.Request) {
	//EnforceSignedInHandler(w, request)
	MyCookieHandler(w, request)

	decoder := json.NewDecoder(request.Body)

	//
	// Process the path variables
	vars := mux.Vars(request)
	table := vars["table"]

	log.Printf("Creating table entry: %s", table)
	var ghost interface{}
	var primary_key string

	switch table {

	case USER_TABLE:
		var t Person
		serr := decoder.Decode(&t)
		if serr != nil {
			log.Printf("The json body isn't json %v", request.Body)
			SendClientErrorBadRequestMessage(w, request, "Malformed JSON body")
			return
		}
		//
		// Start validating the user...
		if len(t.Id) == 0 {
			log.Printf("Missing a username %v", request.Body)
			SendClientErrorBadRequestMessage(w, request, "Malformed JSON body")
			return
		}
		primary_key = t.Id
		ghost = t
		if message, response_code := t.validate(); response_code != 200 {
			SendClientErrorResult(w, request, response_code, message)
			return
		}

	default:
		//SendClientErrorNotFoundResult(w, request, "Command not known")
		Trace.Printf("objectHandler: %v", objectHandler)
		primary_key, ghost = objectHandler.ObjectCreationHandler(table, decoder, w, request)
		if ghost == nil {
			return
		}
	}

	if ghost == nil {
		panic("Unsupported table: " + table)
	} else if len(primary_key) == 0 {
		panic("Generate a priary key using UUID")
	}
	//
	// Insert the object
	log.Printf("Creating object: %v\n", ghost)
	new_object_cursor, err := rethink.Db(DB).Table(table).Insert(ghost).Run(session)
	if err != nil {
		panic(err)
	}
	if new_object_cursor != nil {
		defer new_object_cursor.Close()
	}

	if err != nil {
		Trace.Fprintf(w, "%v", err)
		SendClientErrorInternalServerErrorResult(w, request, err)
	} else {
		type Cursor struct {
			generated_keys []string
		}
		log.Printf("primary key is: %s\n", primary_key)
		var cursor Cursor
		var new_object interface{}
		new_object_cursor.One(&cursor)
		if len(cursor.generated_keys) > 0 {
			primary_key = cursor.generated_keys[0]
		}
		log.Printf("Getting object with key: %s\n", primary_key)
		res, err := rethink.Db(DB).Table(table).Get(primary_key).Run(session)
		log.Printf("      : %v\n", res)
		if res != nil {
			defer res.Close()
		}
		if err != nil {
			log.Fatalf("Error finding object: %s", err)
		}
		res.One(&new_object)

		log.Printf("Marshalling new object: %v", new_object)
		response, new_object_err := json.Marshal(new_object)

		log.Printf("Sending json: %s", response)
		if new_object_err != nil {
			log.Fatalf("Error scanning database result: %s", err)
			SendClientErrorInternalServerErrorResult(w, request, err)
		} else {
			go didCreateTable(table, new_object) // Perform any specific items for this
			SendClientCreatedJsonStringResult(w, request, string(response))
		}
	}
}*/

/*func CreateOrSigninFacebookAccountHandler(w http.ResponseWriter, request *http.Request) {
	MyCookieHandler(w, request)

	//type FacebookSign struct {
	//}
	//
	// Process the path variables
	vars := mux.Vars(request)
	access_token := vars["access_token"]

	res, err := fb.Get("/me", fb.Params{
		"access_token": access_token,
	})

	if err != nil {
		// err can be an facebook API error.
		// if so, the Error struct contains error details.
		SendClientErrorInternalServerErrorResult(w, request, err)
	} else {
		var username string
		//
		// We've received a response from Facebook, now see if an account already exists.
		if user, ok := GetUserByFacebookID(res["id"].(string)); ok {
			Trace.Printf("Userin: %v\n", user)
			SignUserIn(user.Id, w, request)
			SendSignedInObject(w, request, false)

		} else {
			decoder := json.NewDecoder(request.Body)

			type FacebookSigninObject struct {
				Password string `json:"password"`
			}
			var signin_object FacebookSigninObject
			decodeerr := decoder.Decode(&signin_object)
			if decodeerr != nil {
				// Ignore the error since it's not compulsary that the body be present...
			}

			//
			// Proceed to create the account with the FB details

			// First, I need a password for the account.
			if len(signin_object.Password) == 0 {
				SendClientErrorBadRequestMessage(w, request, "Missing password")
				return
			} else if len(signin_object.Password) <= 5 {
				SendClientErrorBadRequestMessage(w, request, "Password must be at least 6 characters long")
				return
			} else if val, ok := res["username"]; ok {
				username = val.(string)
			} else if val, ok := res["email"]; ok {
				username = val.(string)
			} else if val, ok := res["id"]; ok {
				username = val.(string)
			} else {
				panic("Facebook returned a response that didn't include a useable username") //TODO Do somethin more sensible here like insist the client sends a username or email
			}
			Trace.Println("Me %v:", res)
			if DoesUsernameExist(username) {
				SendClientErrorNotAcceptableResultExtra(w, request, "Username is already taken.", map[string]string{"username": username})
			} else {
				// TODO: Any of these could be nil and that'll panic
				// TODO Password hard coded >O_o<
				new_user := Person{username, signin_object.Password, res["first_name"].(string), res["last_name"].(string), "user", res["gender"].(string), res["email"].(string), res["id"].(string)}
				Trace.Printf("Creating a new user: %v\n", new_user)
				response, error := rethink.Db(DB).Table(USER_TABLE).Insert(new_user).Run(session)
				defer response.Close()
				if error != nil {
					Trace.Println("Me %v:", error)
					SendClientErrorInternalServerErrorResult(w, request, error)
				} else {
					Trace.Println("Me %v:", response)
					SignUserIn(username, w, request)
					SendSignedInObject(w, request, true)
				}
			}
		}

	}

	// read my last feed.
	Trace.Println("my latest feed story is:", res.Get("data.0.story"))
}

func EnforceSignedInHandler(w http.ResponseWriter, request *http.Request) bool {
	username := MyCookieHandler(w, request)

	if len(username) == 0 {
		SendClientErrorUnauthorizedResult(w, request, "Please signin")
		return false
	} else {
		return true
	}

}

func GetUserByUsername(username string) (Person, bool) {
	res, err := rethink.Db(DB).Table(USER_TABLE).Get(username).Run(session)
	defer res.Close()
	if err != nil {
		log.Fatalf("Error finding person: %s", err)
	} else if res.IsNil() {
		return Person{}, false
	}
	var user Person
	if err1 := res.One(&user); err1 != nil {
		log.Fatalf("Error getting user: %v", user)
		panic(err1)
	}
	return user, true
}

func DoesUsernameExist(username string) bool {
	res, err := rethink.Db(DB).Table(USER_TABLE).Get(username).Run(session)
	defer res.Close()
	if err != nil {
		log.Fatalf("Error finding person: %s", err)
	}
	return !res.IsNil()
}

func DoesFacebookIDAlreadyExist(facebook_id string) bool {
	res, err := rethink.Db(DB).Table(USER_TABLE).GetAllByIndex("facebook_id", facebook_id).Run(session)
	defer res.Close()
	if err != nil {
		log.Fatalf("Error finding person by facebook id(%s): %s", facebook_id, err)
	}
	return !res.IsNil()
}

func GetUserByFacebookID(facebook_id string) (Person, bool) {
	res, err := rethink.Db(DB).Table(USER_TABLE).GetAllByIndex("facebook_id", facebook_id).Run(session)
	defer res.Close()
	if err != nil {
		log.Fatalf("Error finding person: %s", err)
	} else if res.IsNil() {
		return Person{}, false
	}
	var user Person
	if err1 := res.One(&user); err1 != nil {
		log.Fatalf("Error getting user: %v", user)
		panic(err1)
	}
	return user, true
}

func SendSignedInObject(w http.ResponseWriter, request *http.Request, created bool) {
	username := MyCookieHandler(w, request)
	if len(username) == 0 {
		panic("There's no one logged in")
	}
	p, present := GetUserByUsername(username)
	if present == false {
		panic("Request to send user object that doesn't exist")
	}
	type LoggedInUserResponse struct {
		Person
		Message  string `json:"message"`
		Response string ` json:"response"`
	}
	response := LoggedInUserResponse{p, "Signed in", "ok"}
	response.Password = "" // Remove this from sight!!
	json_body, json_err := json.Marshal(response)
	if json_err != nil {
		SendClientErrorInternalServerErrorResult(w, request, Trace.Errorf("Error reading content on the server."))
	} else {
		if created {
			SendClientCreatedJsonStringResult(w, request, string(json_body))
		} else {
			SendClientOKJsonResult(w, request, string(json_body))
		}
	}

}

func SigninToAccountHandler(w http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)

	type SigninObject struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var signin_object SigninObject
	decodeerr := decoder.Decode(&signin_object)
	if decodeerr != nil {
		panic(decodeerr)
	}
	Trace.Printf("Attempting to sign in user: %v\n", signin_object)
	user, user_error := rethink.Db(DB).Table(USER_TABLE).Get(signin_object.Username).Run(session)
	defer user.Close()
	if user_error != nil {
		log.Fatalf("Error finding person: %s", user_error)
		SendClientErrorInternalServerErrorResult(w, request, user_error)
	}
	if user.IsNil() {
		SendClientErrorUnauthorizedResult(w, request, "Incorrect credentials")
	} else {
		var signedin_user Person
		err := user.One(&signedin_user)

		if err == rethink.ErrEmptyResult {
			log.Fatalf("Error signining in: %s", err)
			SendClientErrorUnauthorizedResult(w, request, "Incorrect credentials")
		} else if err != nil {
			log.Fatalf("Error signining in: %s", err)
			SendClientErrorInternalServerErrorResult(w, request, err)
		} else {
			Trace.Printf("Is %s's password %s and %s equal?\n", signin_object.Username, signin_object.Password, signedin_user.Password)
			if signin_object.Password == signedin_user.Password {
				SignUserIn(signedin_user.Id, w, request)
				SendSignedInObject(w, request, false)
			} else {
				SendClientErrorUnauthorizedResult(w, request, "Incorrect credentials")
			}
		}
	}

}

func AddPushNoteToAccountHandler(w http.ResponseWriter, request *http.Request) {
	if EnforceSignedInHandler(w, request) == false {
		return
	}
	username := MyCookieHandler(w, request)

	decoder := json.NewDecoder(request.Body)

	type NewPushNoteObject struct {
		Token string `json:"token"`
	}

	var new_push_object NewPushNoteObject
	decodeerr := decoder.Decode(&new_push_object)
	if decodeerr != nil {
		panic(decodeerr)
	}
	Trace.Printf("Adding token: %v\n", new_push_object)

	if len(new_push_object.Token) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing token")
	} else {
		user, user_error := rethink.Db(DB).Table(PUSH_TOKEN_TABLE).Get(new_push_object.Token).Run(session)
		defer user.Close()
		if user_error != nil {
			log.Fatalf("Error creating account: %s", user_error)
			SendClientErrorInternalServerErrorResult(w, request, Trace.Errorf("Error occured while creating account"))
		} else if user.IsNil() {
			response, error := rethink.Db(DB).Table(PUSH_TOKEN_TABLE).Insert(PushToken{new_push_object.Token, username, "ios"}).Run(session)
			defer response.Close()
			if error != nil {
				Trace.Println("Me %v:", error)
				SendClientErrorInternalServerErrorResult(w, request, Trace.Errorf("Failed to save push note."))
			} else {
				Trace.Println("Me %v:", response)
				SendClientCreatedOKResult(w, request, "Push received")
			}
		} else {
			// TODO Cgeck if rthe username is different befor doing this
			query := rethink.Db(DB).Table(PUSH_TOKEN_TABLE).Get(new_push_object.Token).Update(map[string]interface{}{"user": username})
			query_session, error := query.Run(session)
			defer query_session.Close()
			if error != nil {
				SendClientErrorInternalServerErrorResult(w, request, Trace.Errorf("Failed to assign new username"))
			} else {
				SendClientOKJsonResult(w, request, "Token is already assigned")
				user2, _ := rethink.Db(DB).Table(USER_TABLE).Get(username).Run(session)
				defer user2.Close()
				var new_user interface{}
				user2.One(&new_user)
				Trace.Printf("Created %v", new_user)
			}
		}
	}
}

func SignupToAccountHandler(w http.ResponseWriter, request *http.Request) {
	decoder := json.NewDecoder(request.Body)
	w.Header().Set("Content-Type", "application/json")

	var signup_object Person
	decodeerr := decoder.Decode(&signup_object)
	if decodeerr != nil {
		panic(decodeerr)
	}
	Trace.Printf("Creating user: %v\n", signup_object)

	if len(signup_object.Id) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing username")
	} else if len(signup_object.Password) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing password")
	} else if len(signup_object.Email) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing email")
	} else if len(signup_object.FirstName) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing firstname")
	} else if len(signup_object.LastName) == 0 {
		SendClientErrorBadRequestMessage(w, request, "Missing lastname")
	} else {
		log.Printf("session: %v\n", signup_object.Id)
		log.Printf("session: %v\n", session)
		user, user_error := rethink.Db(DB).Table(USER_TABLE).Get(signup_object.Id).Run(session)
		defer user.Close()
		if user_error != nil {
			log.Fatalf("Error creating account: %s", user_error)
			SendClientErrorInternalServerErrorResult(w, request, user_error)
		} else if user == nil || user.IsNil() {
			response, error := rethink.Db(DB).Table(USER_TABLE).Insert(signup_object).Run(session)
			defer response.Close()
			if error != nil {
				Trace.Println("Me %v:", error)
				SendClientErrorInternalServerErrorResult(w, request, error)
			} else {
				Trace.Println("Me %v:", response)
				SendClientCreatedJsonStringResult(w, request, "{\"response\":\"ok\"}")

			}
		} else {
			SendClientErrorBadRequestMessage(w, request, "Username is already taken.")
		}
	}
}

func SignOutOfAccountHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("Logging out")
	session, _ := cookie_store.Get(req, "session-name")
	session.Values["signed_in_username"] = ""
	_ = session.Save(req, w)
	w.WriteHeader(http.StatusCreated)
	SendClientOKMessageResult(w, req, "Signed out.")
}

func NotAllowedHandler(w http.ResponseWriter, request *http.Request) {
	SendClientErrorNotAcceptableResult(w, request, "Not Allowed")
}

func ListObjectsHandler(w http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	table := vars["table"]
	query, err := rethink.Db(DB).Table(table).Run(session)
	defer query.Close()
	var all []interface{}
	response_objects := query.All(&all)
	if response_objects != nil {
		panic(response_objects)
	}
	response, err := json.Marshal(all)
	if err != nil {
		log.Fatalf("Error scanning database result: %s", err)
	}
	Trace.Fprintf(w, string(response))

}
*/
/*func getJsonGameResultsResponse(pack_foods_ids []string) ([]byte, error) {
	herofood := AcroMathPayload{Total_rows: len(pack_foods_ids), Offset: 0, Rows: pack_foods_ids}

	response, err := json.MarshalIndent(herofood, "", " ")
	if err != nil {
		return response, err
	}
	return response, err
}
*/

func ReadBodyOrFail(w http.ResponseWriter, r *http.Request, conv interface{} ) ([]byte, error){
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		SendClientErrorInternalServerErrorResult(w, r, err)
		return body, err
	}else {
		err = json.Unmarshal(body, &conv)
		if err != nil {
			log.Panic(err)
			SendClientErrorBadRequestMessage(w, r, err.Error())
			return body, err
		}else {
			return body, err
		}
	}
}

