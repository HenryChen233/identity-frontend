// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
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

// Struct to contain page information
type UpdateInfo struct {
	Email       string `json:"email"`
	Description string `json:"description"`
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

// Preload the information by fetching data from backend
func readFromBackend(userid string) (*Profile, error) {
	apiUrl := "http://localhost:8080/v1/accounts/@me"
	res, err := http.Get(apiUrl)
	if err != nil {
		log.Println(err)
	}
	defer res.Body.Close()
	bodyBytes, err := ioutil.ReadAll(res.Body)
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
		log.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageData PublicInfo
	err = json.Unmarshal(bodyBytes, &pageData)
	if err != nil {
		log.Println(err)
	}
	return &pageData, err
}

//
func accountsHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := readFromPublic(title)
	if err != nil {
		log.Println(err)
	}

	page := Profile{}
	page.Username = p.Username
	page.Description = p.Description
	renderTemplate(w, "public_profile", &page)
}

// Render the edit information page
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
	p, err := readFromBackend(title)
	if err != nil {
		log.Println(err)
	}
	renderTemplate(w, "edit", p)
}

// The Function to save the edited information
func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
	email := r.FormValue("email")
	description := r.FormValue("description")
	originalPage, err := readFromBackend(title)
	if err != nil {
		log.Println(err)
	}
	// Get cookie from browser
	cookie, err := r.Cookie("name-cookie")
	// Change the information from preloaded information
	originalPage.Email = email
	originalPage.Description = description
	updateInfo := UpdateInfo{}
	updateInfo.Email = email
	updateInfo.Description = description
	// Json format transformation
	jsonData, err := json.Marshal(updateInfo)
	if err != nil {
		log.Println(err)
	}
	Data := string(jsonData)
	payload := strings.NewReader(Data)
	// Send http request
	link := "http://localhost:8080/v1/accounts/@me?token=" + cookie.Value
 	client := &http.Client{}
	request, err := http.NewRequest("PUT", link, payload)
	request.Header.Add("Content-Type", "application/json")
	_, err = client.Do(request)
	client.CloseIdleConnections()
	if err != nil {
		log.Println(err)
	}
	// After edited it redirect to the private information page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

// Load html template
var templates = template.Must(template.ParseFiles("template/edit.html", "template/accounts.html", "template/register.html", "template/login.html", "template/public_profile.html", "template/profile.html", "template/loginError.html", "template/ChangePassword.html"))

//
func renderTemplate(w http.ResponseWriter, tmpl string, p *Profile) {
	err := templates.ExecuteTemplate(w, tmpl+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Regular expression to avoid illegal request
var validPath = regexp.MustCompile("^(/(edit|accounts|home)/([a-zA-Z0-9]+))|(/(login|home|create|privatePage|register|logout|save|loginError)/)$")

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

//
func passwordHandler()  {

}

//
func savepasswordHandler() {

}

//
func createHandler(w http.ResponseWriter, r *http.Request, title string){
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
		log.Println(err)
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
		log.Println(err)
	}
	// Log in with newly created account information
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	Cookie := http.Cookie{Name:"name-cookie",
		Value: token,
		Path: "/",
		HttpOnly:true}
	http.SetCookie(w, &Cookie)
	// Set the cookie to the browser
	if err != nil {
		log.Println(err)
	}
	// After log in, redirect to the personal private page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

// Handle the login page
func homeHandler(w http.ResponseWriter, r *http.Request, title string) {
	p := Profile{}
	renderTemplate(w, "login", &p)
}

//
func loginHandler(w http.ResponseWriter, r *http.Request, title string) {
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
	if response.StatusCode == 401 {
		http.Redirect(w, r, "/loginError/", http.StatusFound)
	}
	if err != nil {
		log.Println(err)
	}
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	fmt.Println(token)
	// Set the cookies to the browser
	Cookie := http.Cookie{Name:"name-cookie",
		Value: token,
		Path:"/",
		HttpOnly:true}
	http.SetCookie(w, &Cookie)
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

//
func registerHandler(w http.ResponseWriter, r *http.Request, title string) {
	p := Profile{}
	renderTemplate(w, "register", &p)
}

//
func privateHandler(w http.ResponseWriter, r *http.Request, title string) {
	//fmt.Println("Cookie.......")
	// Read cookie from browser
	cookie,_ := r.Cookie("name-cookie")
	link := "http://localhost:8080/v1/accounts/@me?token="+ cookie.Value
	resp, err := http.Get(link)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	// Read personal profile data from backend and transform to our data format
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageInfo = Profile{}
	err = json.Unmarshal(bodyBytes, &pageInfo)
	fmt.Println(pageInfo)
	if err != nil {
		log.Println(err)
	}
	renderTemplate(w, "profile", &pageInfo)
}

// Handle error when having wrong password and let user to re-enter password
func errorPasswordHandler(w http.ResponseWriter, r *http.Request, title string){
	p := Profile{}
	renderTemplate(w, "loginError", &p)
}

// When user need to log out, this handler would erase the cookie to clean up the log in status.
func logoutHandler(w http.ResponseWriter, r *http.Request, title string){
	logOutCookie := http.Cookie{Name:"name-cookie",
		Path:"/",
		MaxAge:-1}
	http.SetCookie(w, &logOutCookie)
	http.Redirect(w, r, "/home/",http.StatusFound)
}


//
func main() {
	http.HandleFunc("/accounts/", makeHandler(accountsHandler))
	http.HandleFunc("/edit/", makeHandler(editHandler))
	http.HandleFunc("/save/", makeHandler(saveHandler))
	http.HandleFunc("/register/", makeHandler(registerHandler))
	http.HandleFunc("/create/", makeHandler(createHandler))
	http.HandleFunc("/login/", makeHandler(loginHandler))
	http.HandleFunc("/home/", makeHandler(homeHandler))
	http.HandleFunc("/privatePage/", makeHandler(privateHandler))
	http.HandleFunc("/logout/", makeHandler(logoutHandler))
	http.HandleFunc("/loginError/", makeHandler(errorPasswordHandler))
	log.Println(http.ListenAndServe(":5000", nil))
}