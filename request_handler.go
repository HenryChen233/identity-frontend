package main

import (
	"encoding/json"
	"flag"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type profile struct {
	Username    string `json:"username"`
	Firstname   string `json:"firstName"`
	Lastname    string `json:"lastName"`
	Email       string `json:"email"`
	Description string `json:"description"`
	Password    string `json:"password"`
	Verified    string `json:"verified"`
}

type updateDescription struct {
	Username    string `json:"username"`
	Description string `json:"description"`
	Token       string `json:"token"`
}

type updateEmail struct {
	Username    string `json:"username"`
	Email       string 	`json:"email"`
	Token       string 	`json:"token"`
}

type publicInfo struct {
	Username    string `json:"username"`
	Description string `json:"description"`
}

type logInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//UpdatePassword Wrap up info to update password with CSRF token
type updatePassword struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

//TokenInfo to store the token value and type
type TokenInfo struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}



const (
	backendURI       = "/v1"
	timeoutInSeconds = 10
)

var (
	backendAddr, backendURL string
	client                  = &http.Client{
		Timeout: time.Second * timeoutInSeconds,
	}
	templates = template.Must(template.ParseGlob("./template/*.html"))
)


func instanceToPayLoad(info interface{}) (*strings.Reader, error) {
	tokenData, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	tokenBuffer := string(tokenData)
	return strings.NewReader(tokenBuffer), nil
}

func renderTemplate(w http.ResponseWriter, tmplName string, p *profile) {
	err := templates.ExecuteTemplate(w, tmplName+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readMyProfile(cookieValue string) (*profile, error) {
	url := backendURL + "/accounts/@me"
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	request.Header.Add("Cookie", "V="+cookieValue)
	resp, err := client.Do(request)
	if err != nil {
		log.Println("Cookie may expire ", err)
		return nil, err
	}
	defer resp.Body.Close()
	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var pageInfo profile
	err = json.Unmarshal(bs, &pageInfo)
	if err != nil {
		return nil, err
	}
	return &pageInfo, err
}

// Function to read public information without login and render the web pages
func readUserProfile(username string) (*publicInfo, error) {
	url := backendURL + "/accounts/" + username
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bs, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var pageData publicInfo
	err = json.Unmarshal(bs, &pageData)
	if err != nil {
		return nil, err
	}

	return &pageData, err
}

//
func accountsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Path[len("/accounts/"):]
	p, err := readUserProfile(username)
	if err != nil {
		log.Println("account does not exist", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}

	page := profile{Username: p.Username,
		Description: p.Description}
	renderTemplate(w, "public_profile", &page)
}

// Render the edit information page
func editHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("V")
	if err != nil || cookie == nil {
		log.Println("May log out or cookie expire", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Prefetch from backend API
	p, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("error happened when getting profile",err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	//
	token := TokenInfo{"", "STANDARD"}
	tokenPayload, err := instanceToPayLoad(token)
	if err != nil {
		log.Println("error when decoding JSON", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Get token request
	getTokenURL := backendURL + "/tokens/"
	response, err := sendRequest(getTokenURL, client, tokenPayload, cookie, "POST")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("error occurred when reading response", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		log.Println("Decode response error",err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	updateNormal := updateDescription{p.Username, p.Description, token.Value}
	renderTemplateDescription(w, "edit", &updateNormal)
}

func sendRequest(link string, client *http.Client, payload *strings.Reader, cookie *http.Cookie, method string)(*http.Response, error) {
	var request *http.Request
	var err error
	if method == "POST" || method == "PUT"{
		request, err = http.NewRequest(method, link, payload)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	} else{
		request, err = http.NewRequest(method, link,nil)
		if err != nil {
			log.Println(err)
			return nil, err
		}
	}

	if method == "PUT" || method =="POST"{
		request.Header.Add("Content-Type", "application/json")
	}
	//request.Header.Add("Cookie", "V=" + cookieValue)

	request.AddCookie(cookie)
	log.Println("cookie:")
	log.Print(cookie)

	log.Println(request)
	resp, err := client.Do(request)
	if err != nil || resp.StatusCode == 500{
		log.Println("empty response:", err)
		return resp, err
	}
	client.CloseIdleConnections()
	return resp, err
}

// The Function to save the edited information
func saveEditedInfo(w http.ResponseWriter, r *http.Request) {
	description := r.FormValue("description")
	token := r.FormValue("CSRFToken")
	// Get cookie from browser
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	originalPage, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("cookie may expire and need to login again ", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Change the information from preloaded information
	updateInfo := updateDescription{Description: description,
		Username: originalPage.Username,
		Token :""}
	// Json format transformation
	payload, err := instanceToPayLoad(updateInfo)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Send http request
	link := backendURL + "/accounts/@me?token=" + token
	_ ,err = sendRequest(link, client, payload, cookie,"PUT")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

func passwordHandler(w http.ResponseWriter, r *http.Request) {
	// Get cookie
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println("cookie may expire login again", err)
		// When refactoring the code, a more specific page may needed
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Prefetch info to render pages from backend API
	p, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("cookie may expire login again", err)
		// When refactoring the code, a more specific page may needed
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Set token struct to get token
	token := TokenInfo{}
	token.Type = "CRITICAL"
	token.Value = ""
	tokenPayload, err := instanceToPayLoad(token)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Get token request
	getTokenURL := backendURL + "/tokens/"
	response, err := sendRequest(getTokenURL, client, tokenPayload, cookie, "POST")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	updatePassword := updatePassword{}
	updatePassword.Username = p.Username
	updatePassword.Password = ""
	updatePassword.Token = token.Value
	renderTemplatePassword(w, "changePassword", &updatePassword)
}

func passwordSaveHandler(w http.ResponseWriter, r *http.Request) {
	newPassword := r.FormValue("newpassword")
	passwordConfirm := r.FormValue("passwordconfirm")
	token := r.FormValue("token")
	// Get cookie from browser
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println("login expire, log in again", err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	originalProfile, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("login expire, log in again", err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	if newPassword != passwordConfirm {
		log.Println("password does not match", err)
		http.Redirect(w, r, "/password/", http.StatusFound)
		return
	}
	updatePassword := updatePassword{
		Username: originalProfile.Username,
		Password: newPassword,
		Token:    token}
	// Struct to JSON payload
	payload, err := instanceToPayLoad(updatePassword)
	if err != nil {
		log.Println("Json transfer failure", err)
		http.Redirect(w, r, "/password/", http.StatusFound)
		return
	}
	// Send http request
	link := backendURL + "/accounts/@me?token=" + token
	_, err = sendRequest(link, client, payload, cookie,"PUT")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
	return
}

//
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Get user login in information
	username := r.FormValue("username")
	password := r.FormValue("password")
	// Encode the log in data to the json format payload
	user := logInfo{username, password}
	payload, err := instanceToPayLoad(user)
	if err != nil {
		log.Println("Json decode error", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	response, err := http.Post("http://localhost:8080/v1/sessions/", "application/json", payload)
	if err != nil || response.StatusCode == 401 {
		log.Println("login Failure", err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	// Set the cookies to the browser
	cookieValue := strings.TrimPrefix(token, "V=")
	cookieValue = strings.TrimSuffix(cookieValue, "Version=1")
	Cookie := http.Cookie{Name: "V",
		Value:    cookieValue,
		Path:     "/",
		HttpOnly: true}
	http.SetCookie(w, &Cookie)
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
	return
}

func editEmailHandler(w http.ResponseWriter, r *http.Request){
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println("cookie may expire login again", err)
		// When refactoring the code, a more specific page may needed
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Prefetch info to render pages from backend API
	p, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("cookie may expire login again", err)
		// When refactoring the code, a more specific page may needed
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Set token struct to get token
	token := TokenInfo{}
	token.Type = "CRITICAL"
	token.Value = ""
	tokenPayload, err := instanceToPayLoad(token)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	// Get token request
	getTokenURL := backendURL + "/tokens/"
	request, err := http.NewRequest("POST", getTokenURL, tokenPayload)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Cookie", "V="+cookie.Value)
	response, err := client.Do(request)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	err = json.Unmarshal(bodyBytes, &token)
	defer client.CloseIdleConnections()
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	updateEmail := updateEmail{p.Username, p.Email, token.Value}
	renderTemplateEmail(w, "editEmail", &updateEmail)
}

func emailSaveHandler(w http.ResponseWriter, r *http.Request){
	newEmail := r.FormValue("email")
	token := r.FormValue("CSRFToken")
	// Get cookie from browser
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println("login expire, log in again", err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	originalProfile, err := readMyProfile(cookie.Value)
	if err != nil {
		log.Println("login expire, log in again", err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	updateEmail := updateEmail{
		Username: originalProfile.Username,
		Email:newEmail,
		Token:""}
	// Struct to JSON payload
	payload, err := instanceToPayLoad(updateEmail)
	if err != nil {
		log.Println("Json transfer failure", err)
		http.Redirect(w, r, "/editEmail/", http.StatusFound)
		return
	}
	// Send http request
	link := backendURL + "/accounts/@me?token=" + token
	_, err = sendRequest(link, client, payload, cookie, "PUT")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
	return

}
//
func registerHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "register", &p)
}

//
func privateHandler(w http.ResponseWriter, r *http.Request) {
	// Read cookie from browser
	cookie, err := r.Cookie("V")
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/loginError/", http.StatusFound)
		return
	}
	resp, err := sendRequest("http://localhost:8080/v1/accounts/@me", client, nil, cookie, "GET")
	// Read personal profile data from backend and transform to our data format
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageInfo = profile{}
	err = json.Unmarshal(bodyBytes, &pageInfo)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	renderTemplate(w, "profile", &pageInfo)
}

//
func createHandler(w http.ResponseWriter, r *http.Request) {
	var pageInfo profile
	pageInfo.Username = r.FormValue("username")
	pageInfo.Firstname = r.FormValue("firstname")
	pageInfo.Lastname = r.FormValue("lastname")
	pageInfo.Description = r.FormValue("description")
	pageInfo.Password = r.FormValue("password")
	pageInfo.Email = r.FormValue("email")
	pageInfo.Verified = "true"
	// Encode data to Json
	payload, err := instanceToPayLoad(pageInfo)
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	link := backendURL+"/accounts/"
	_, err = sendRequest(link, client, payload, nil, "POST")
	user := logInfo{pageInfo.Username,pageInfo.Password}
	payload,err = instanceToPayLoad(user)
	link = backendURL+"/sessions/"
	response, err := sendRequest(link, client, payload, nil, "POST")
	if err != nil {
		log.Println(err)
	}
	// Log in with newly created account information
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	Cookie := http.Cookie{Name: "V",
		Value:    token,
		Path:     "/",
		HttpOnly: true}
	http.SetCookie(w, &Cookie)
	// Set the cookie to the browser
	if err != nil {
		log.Println(err)
	}
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

// Handle the login page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "login", &p)
}

func renderTemplateDescription(w http.ResponseWriter, tmpl string, p *updateDescription) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func renderTemplateEmail(w http.ResponseWriter, tmpl string, p *updateEmail){
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}


func renderTemplatePassword(w http.ResponseWriter, tmpl string, p *updatePassword) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// Regular expression to avoid illegal request
var validPath = regexp.MustCompile("^(/(edit|accounts|home)/([a-zA-Z0-9]+))|(/(login|home|create|privatePage|register|logout|save|loginError|password|passwordsave|editEmail|emailSave)/)$")

func makeHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r)
	}
}

// Handle error when having wrong password and let user to re-enter password
func errorPasswordHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "loginError", &p)
}

// When user need to log out, this handler would erase the cookie to clean up the log in status.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	logOutCookie := http.Cookie{Name: "V",
		Path:   "/",
		MaxAge: -1}
	http.SetCookie(w, &logOutCookie)
	http.Redirect(w, r, "/home/", http.StatusFound)
}

//
func main() {
	flag.StringVar(&backendAddr, "backend", "localhost:8080", "backend IP and port")
	flag.Parse()
	backendURL = "http://" + backendAddr + backendURI
	http.HandleFunc("/accounts/", makeHandler(accountsHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveEditedInfo))
	http.HandleFunc("/register/", makeHandler(registerHandler))
	http.HandleFunc("/create/", makeHandler(createHandler))
	http.HandleFunc("/login/", makeHandler(loginHandler))
	http.HandleFunc("/home/", makeHandler(homeHandler))
	http.HandleFunc("/privatePage/", makeHandler(privateHandler))
	http.HandleFunc("/logout/", makeHandler(logoutHandler))
	http.HandleFunc("/loginError/", makeHandler(errorPasswordHandler))
	http.HandleFunc("/password/", makeHandler(passwordHandler))
	http.HandleFunc("/passwordsave/", makeHandler(passwordSaveHandler))
	http.HandleFunc("/editEmail/", makeHandler(editEmailHandler))
	http.HandleFunc("/emailSave/", makeHandler(emailSaveHandler))
	log.Println(http.ListenAndServe(":5000", nil))
}
