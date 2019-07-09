// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// Contains all the information about user's information
type Profile struct {
	Username    string `json:"username"`
	Firstname   string `json:"firstName"`
	Lastname    string `json:"lastName"`
	Email       string `json:"email"`
	Description string `json:"description"`
	Password    string `json:"password"`
	Verified    string `json:"verified"`
}

// Struct to contain page information using to update normal information
type UpdateDescription struct {
	Username    string `json:"username"`
	Description string `json:"description"`
	Token       string `json:"token"`
}

// Wrap up info to update email with CSRF token
type UpdateEmail struct {
	Username    string `json:"username"`
	Email string `json:"email"`
	Token       string `json:"token"`
}
// Wrap up info to update password with CSRF token
type UpdatePassword struct {
	Username    string `json:"username"`
	Password string `json:"password"`
	Token       string `json:"token"`
}


//Struct to store updated information
type PublicInfo struct {
	Username    string `json:"username"`
	Description string `json:"description"`
}

//Struct to store public page information
type LogInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type TokenInfo struct{
	Value string 	`json:"value"`
	Type  string	`json:"type"`
}

// Preload the information by fetching data from backend
func readProfile(r *http.Request, w http.ResponseWriter) (*Profile, error) {
	apiUrl := "http://localhost:8080/v1/accounts/@me"
	client := &http.Client{}
	request, err := http.NewRequest("GET", apiUrl,nil)
	Cookie, err := r.Cookie("V")
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	request.Header.Add("Cookie", strings.TrimPrefix(Cookie.Value, "cookie="))
	resp, err := client.Do(request)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	// Extract data from response and turn to pageInfo type
	var pageInfo Profile
	err = json.Unmarshal(bodyBytes, &pageInfo)
	if err != nil {
		log.Println(err)
	}
	return &pageInfo, err
}

// Function to read public information without login and render the web pages
func readFromPublic(username string) (*PublicInfo, error) {
	link := "http://localhost:8080/v1/accounts/" + username
	resp, err := http.Get(link)
	if err != nil {
		log.Println("account does not exists")
	}
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageData PublicInfo
	err = json.Unmarshal(bodyBytes, &pageData)
	return &pageData, err
}

//
func accountsHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := readFromPublic(title)
	if err != nil {
		log.Println("account does not exist")
	}
	page := Profile{}
	page.Username = p.Username
	page.Description = p.Description
	renderTemplate(w, "public_profile", &page)
}

// Render the edit information page
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := readProfile(r, w)
	if err != nil {
		log.Println(err)
	}
	client := &http.Client{}
	// Get cookie
	cookie, err := r.Cookie("V")
	cookieValue := strings.TrimPrefix(cookie.Value, "cookie=")
	//
	token := TokenInfo{}
	token.Type = "STANDARD"
	token.Value = ""
	tokenData, err := json.Marshal(token)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	tokenBuffer := string(tokenData)
	tokenPayload := strings.NewReader(tokenBuffer)
	// Get token request
	getTokenUrl := "http://localhost:8080/v1/tokens"
	request, err := http.NewRequest("POST",getTokenUrl,tokenPayload)
	if err != nil {
		log.Println(err)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Cookie", cookieValue)
	response, err :=client.Do(request)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(bodyBytes, &token)
	if err != nil {
		log.Println(err)
	}
	updateNormal := UpdateDescription{}
	updateNormal.Username = p.Username
	updateNormal.Description = p.Description
	updateNormal.Token = token.Value
	renderTemplateDescription(w, "edit", &updateNormal)
}

// The Function to save the edited information
func saveEditedInfo(w http.ResponseWriter, r *http.Request, title string) {
	description := r.FormValue("description")
	token := r.FormValue("CSRFToken")
	originalPage, err := readProfile(r, w)
	if err != nil {
		log.Println(err)
	}

	// Get the standard token to change the regular information
	client := &http.Client{}

	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	// Change the information from preloaded information
	updateInfo := UpdateDescription{}
	updateInfo.Username = originalPage.Username
	updateInfo.Token = token
	updateInfo.Description = description
	// Json format transformation
	jsonData, err := json.Marshal(updateInfo)
	if err != nil {
		log.Println(err)
	}
	Data := string(jsonData)
	payload := strings.NewReader(Data)
	// Send http request
	link := "http://localhost:8080/v1/accounts/@me"
	request, err := http.NewRequest("PUT", link, payload)

	// Get cookie from browser
	cookie, err := r.Cookie("V")
	cookieValue := strings.TrimPrefix(cookie.Value, "cookie=")
	request.Header.Add("Cookie", cookieValue)
	request.Header.Add("Content-Type", "application/json")
	_, err = client.Do(request)
	client.CloseIdleConnections()
	if err != nil {
		log.Println(err)
	}
	// After edited it redirect to the private information page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

func passwordHandler(w http.ResponseWriter, r *http.Request)  {
	p,err := readProfile(r, w)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	client := &http.Client{}
	// Get cookie
	cookie, err := r.Cookie("V")
	cookieValue := strings.TrimPrefix(cookie.Value, "cookie=")
	//
	token := TokenInfo{}
	token.Type = "CRITICAL"
	token.Value = ""
	tokenData, err := json.Marshal(token)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	tokenBuffer := string(tokenData)
	tokenPayload := strings.NewReader(tokenBuffer)
	// Get token request
	getTokenUrl := "http://localhost:8080/v1/tokens"
	request, err := http.NewRequest("POST",getTokenUrl,tokenPayload)
	if err != nil {
		log.Println(err)
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Cookie", cookieValue)
	response, err :=client.Do(request)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	err = json.Unmarshal(bodyBytes, &token)
	client.CloseIdleConnections()
	if err != nil {
		log.Println(err)
	}
	updatePassword := UpdatePassword{}
	updatePassword.Username = p.Username
	updatePassword.Password = ""
	updatePassword.Token = token.Value
	renderTemplatePassword(w, "changePassword", &updatePassword)
}

func passwordSaveHandler(w http.ResponseWriter, r *http.Request){
	newPassword := r.FormValue("newpassword")
	passwordConfirm := r.FormValue("passwordconfirm")
	token := r.FormValue("token")
	originalProfile, err := readProfile(r, w)
	if err != nil {
		http.Redirect(w, r, "/home/", http.StatusFound)
		log.Println("login expire, log in again")
	}
	if newPassword != passwordConfirm {
		http.Redirect(w, r, "/password/", http.StatusFound)
	}
	updatePassword := UpdatePassword{}
	updatePassword.Username = originalProfile.Username
	updatePassword.Password = newPassword
	updatePassword.Token = token
	client := &http.Client{}
	// Json format transformation
	jsonData, err := json.Marshal(updatePassword)
	Data := string(jsonData)
	payload := strings.NewReader(Data)
	// Send http request
	link := "http://localhost:8080/v1/accounts/@me"
	request, err := http.NewRequest("PUT", link, payload)

	// Get cookie from browser
	cookie, err := r.Cookie("V")
	cookieValue := strings.TrimPrefix(cookie.Value, "cookie=")
	request.Header.Add("Cookie", cookieValue)
	request.Header.Add("Content-Type", "application/json")
	response, err := client.Do(request)
	if response.StatusCode == 500 {
		http.Redirect(w, r, "/password/", http.StatusFound)
		log.Println("Error Occur when changing password")
	}
	client.CloseIdleConnections()
	if err != nil {
		http.Redirect(w, r, "/password/", http.StatusFound)
	}
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

//
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Get user login in information
	username := r.FormValue("username")
	password := r.FormValue("password")
	// Encode the log in data to the json format payload
	user := LogInfo{}
	user.Username = username
	user.Password = password
	userData, err := json.Marshal(user)
	userString := string(userData)
	payload := strings.NewReader(userString)
	response, err := http.Post("http://localhost:8080/v1/sessions/", "application/json", payload)
	if response.StatusCode == 401 || err != nil{
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	// Set the cookies to the browser
	Cookie := http.Cookie{Name:"V",
		Value: token,
		Path:"/",
		HttpOnly:true}
	http.SetCookie(w, &Cookie)
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

//
func registerHandler(w http.ResponseWriter, r *http.Request) {
	p := Profile{}
	renderTemplate(w, "register", &p)
}

//
func privateHandler(w http.ResponseWriter, r *http.Request) {
	// Read cookie from browser
	cookie,_ := r.Cookie("V")
	client := &http.Client{
	}
	req, err := http.NewRequest("GET", "http://localhost:8080/v1/accounts/@me",nil)
	cookieValue := strings.TrimPrefix(cookie.Value, "cookie=")
	req.Header.Add("Cookie", cookieValue)
	resp, err := client.Do(req)
	if err != nil {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	defer resp.Body.Close()
	// Read personal profile data from backend and transform to our data format
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageInfo = Profile{}
	err = json.Unmarshal(bodyBytes, &pageInfo)
	if err != nil {
		http.Redirect(w, r, "/home/", http.StatusFound)
	}
	renderTemplate(w, "profile", &pageInfo)
}

//
func createHandler(w http.ResponseWriter, r *http.Request){
	var pageinfo Profile
	pageinfo.Username = r.FormValue("username")
	pageinfo.Firstname = r.FormValue("firstname")
	pageinfo.Lastname = r.FormValue("lastname")
	pageinfo.Description = r.FormValue("description")
	pageinfo.Password = r.FormValue("password")
	pageinfo.Email = r.FormValue("email")
	pageinfo.Verified = "true"
	// Read information from frontend page
	newUser, err := json.Marshal(pageinfo)
	if err != nil {
		log.Println(err)
	}
	Data := string(newUser)
	payload := strings.NewReader(Data)
	// Encode data to Json
	_, err = http.Post("http://localhost:8080/v1/accounts/", "application/json", payload)
	if err != nil {
		http.Redirect(w, r, "/create/",http.StatusFound)
	}
	// Send the request to create a new account

	user := LogInfo{}
	user.Username = pageinfo.Username
	user.Password = pageinfo.Password
	userData, err := json.Marshal(user)
	userString := string(userData)
	payload = strings.NewReader(userString)
	response, err := http.Post("http://localhost:8080/v1/sessions/", "application/json", payload)
	if err != nil {
		http.Redirect(w, r, "/home/", http.StatusFound)
	}
	// Log in with newly created account information
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	// Set the cookie to the browser
	Cookie := http.Cookie{Name:"V",
		Value: token,
		Path: "/",
		HttpOnly:true}
	http.SetCookie(w, &Cookie)
	// After log in, redirect to the personal private page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

// Handle the login page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	p := Profile{}
	renderTemplate(w, "login", &p)
}
// Handle error when having wrong password and let user to re-enter password
func errorPasswordHandler(w http.ResponseWriter, r *http.Request){
	p := Profile{}
	renderTemplate(w, "loginError", &p)
}

// When user need to log out, this handler would erase the cookie to clean up the log in status.
func logoutHandler(w http.ResponseWriter, r *http.Request){
	logOutCookie := http.Cookie{Name:"V",
		Path:"/",
		MaxAge:-1}
	http.SetCookie(w, &logOutCookie)
	http.Redirect(w, r, "/home/",http.StatusFound)
}


// Load html template
var templates = template.Must(template.ParseFiles("template/edit.html", "template/accounts.html", "template/register.html", "template/login.html", "template/public_profile.html", "template/profile.html", "template/loginError.html", "template/changePassword.html"))

//
func renderTemplate(w http.ResponseWriter, tmpl string, p *Profile) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderTemplateDescription(w http.ResponseWriter, tmpl string, p *UpdateDescription){
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func renderTemplatePassword(w http.ResponseWriter, tmpl string, p *UpdatePassword){
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Regular expression to avoid illegal request
var validPath = regexp.MustCompile("^(/(edit|accounts|home)/([a-zA-Z0-9]+))|(/(login|home|create|privatePage|register|logout|save|loginError|password)/)$")

//
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := validPath.FindStringSubmatch(r.URL.Path)
		if m == nil {
			http.NotFound(w, r)
			return
		}
		fn(w, r, m[3])
	}
}

func makeHandlerNoParameter(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r)
	}
}

//
func main() {
	http.HandleFunc("/accounts/", makeHandler(accountsHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveEditedInfo))
	http.HandleFunc("/register/", makeHandlerNoParameter(registerHandler))
	http.HandleFunc("/create/", makeHandlerNoParameter(createHandler))
	http.HandleFunc("/login/", makeHandlerNoParameter(loginHandler))
	http.HandleFunc("/home/", makeHandlerNoParameter(homeHandler))
	http.HandleFunc("/privatePage/", makeHandlerNoParameter(privateHandler))
	http.HandleFunc("/logout/", makeHandlerNoParameter(logoutHandler))
	http.HandleFunc("/loginError/", makeHandlerNoParameter(errorPasswordHandler))
	http.HandleFunc("/password/", makeHandlerNoParameter(passwordHandler))
	http.HandleFunc("/passwordsave/", makeHandlerNoParameter(passwordSaveHandler))
	log.Println(http.ListenAndServe(":5000", nil))
}