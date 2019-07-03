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
	"strings"
	"time"
)

// The following structs are declared to enable the use of JSON Marshalling

type profile struct {
	Username    string `json:"username"`
	Firstname   string `json:"firstName"`
	Lastname    string `json:"lastName"`
	Email       string `json:"email"`
	Description string `json:"description"`
	Password    string `json:"password"`
	Verified    string `json:"verified"`
}

type updateInfo struct {
	Email       string `json:"email"`
	Description string `json:"description"`
}

type publicInfo struct {
	Username    string `json:"username"`
	Description string `json:"description"`
}

type logInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	backendURL       = "http://localhost:8080/v1"
	timeoutInSeconds = 10
)

var (
	client = &http.Client{
		Timeout: time.Second * timeoutInSeconds,
	}
	templates = template.Must(template.ParseGlob("./template/*.html"))
)

func renderTemplate(w http.ResponseWriter, tmplName string, p *profile) {
	err := templates.ExecuteTemplate(w, tmplName+".html", p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func readMyProfile() (*profile, error) {
	url := backendURL + "/accounts/@me"
	resp, err := client.Get(url)
	if err != nil {
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
		log.Println(err)
	}

	page := profile{}
	page.Username = p.Username
	page.Description = p.Description
	renderTemplate(w, "public_profile", &page)
}

// Render the edit information page
func editHandler(w http.ResponseWriter, r *http.Request) {
	p, err := readMyProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	renderTemplate(w, "edit", p)
}

// The Function to save the edited information
func saveHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	description := r.FormValue("description")
	originalPage, err := readMyProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get cookie from browser
	cookie, err := r.Cookie("name-cookie")
	// Change the information from preloaded information
	originalPage.Email = email
	originalPage.Description = description
	updateInfo := updateInfo{}
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
	link := backendURL + "/accounts/@me?token=" + cookie.Value
	request, err := http.NewRequest("PUT", link, payload)
	request.Header.Add("Content-Type", "application/json")
	_, err = client.Do(request)
	if err != nil {
		log.Println(err)
	}
	// After edited it redirect to the private information page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

//
func passwordHandler() {

}

//
func savepasswordHandler() {

}

//
func createHandler(w http.ResponseWriter, r *http.Request) {
	var pageinfo profile
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
	_, err = client.Post(backendURL+"/accounts/", "application/json", payload)
	if err != nil {
		log.Println(err)
	}
	// Send the request to create a new account

	user := logInfo{}
	user.Username = pageinfo.Username
	user.Password = pageinfo.Password
	userData, err := json.Marshal(user)
	userString := string(userData)
	payload = strings.NewReader(userString)
	response, err := client.Post(backendURL+"/sessions/", "application/json", payload)
	if err != nil {
		log.Println(err)
	}
	// Log in with newly created account information
	// Get token from login response from backend
	token := response.Header.Get("Set-Cookie")
	Cookie := http.Cookie{Name: "name-cookie",
		Value:    token,
		Path:     "/",
		HttpOnly: true}
	http.SetCookie(w, &Cookie)
	// Set the cookie to the browser
	if err != nil {
		log.Println(err)
	}
	// After log in, redirect to the personal private page
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

// Handle the login page
func homeHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "login", &p)
}

//
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Get user login in information
	username := r.FormValue("username")
	password := r.FormValue("password")
	// Encode the log in data to the json format payload
	user := logInfo{}
	user.Username = username
	user.Password = password
	userData, err := json.Marshal(user)
	userString := string(userData)
	payload := strings.NewReader(userString)
	response, err := client.Post(backendURL+"/sessions/", "application/json", payload)
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
	Cookie := http.Cookie{Name: "name-cookie",
		Value:    token,
		Path:     "/",
		HttpOnly: true}
	http.SetCookie(w, &Cookie)
	http.Redirect(w, r, "/privatePage/", http.StatusFound)
}

//
func registerHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "register", &p)
}

//
func privateHandler(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("Cookie.......")
	// Read cookie from browser
	cookie, _ := r.Cookie("name-cookie")
	link := backendURL + "/accounts/@me?token=" + cookie.Value
	resp, err := client.Get(link)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	// Read personal profile data from backend and transform to our data format
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	var pageInfo = profile{}
	err = json.Unmarshal(bodyBytes, &pageInfo)
	fmt.Println(pageInfo)
	if err != nil {
		log.Println(err)
	}
	renderTemplate(w, "profile", &pageInfo)
}

// Handle error when having wrong password and let user to re-enter password
func errorPasswordHandler(w http.ResponseWriter, r *http.Request) {
	p := profile{}
	renderTemplate(w, "loginError", &p)
}

// When user need to log out, this handler would erase the cookie to clean up the log in status.
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	logOutCookie := http.Cookie{Name: "name-cookie",
		Path:   "/",
		MaxAge: -1}
	http.SetCookie(w, &logOutCookie)
	http.Redirect(w, r, "/home/", http.StatusFound)
}

//
func main() {
	http.HandleFunc("/accounts/", accountsHandler)
	http.HandleFunc("/edit/", editHandler)
	http.HandleFunc("/save/", saveHandler)
	http.HandleFunc("/register/", registerHandler)
	http.HandleFunc("/create/", createHandler)
	http.HandleFunc("/login/", loginHandler)
	http.HandleFunc("/home/", homeHandler)
	http.HandleFunc("/privatePage/", privateHandler)
	http.HandleFunc("/logout/", logoutHandler)
	http.HandleFunc("/loginError/", errorPasswordHandler)
	log.Println(http.ListenAndServe(":5000", nil))
}
