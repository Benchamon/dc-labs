package main

import(
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"time"
	"strconv"
	
)

type Session struct{
	User string
	Token string
}

var sessionController []Session 

/*
 * Converts bytes to Kb or Mb
 **/
func imgSize(size int64) (string, bool){
	var KB, MB, Max float64 = 1024, 1048576, 10485760
	FloatS := float64(size)
	if FloatS < KB{
		return strconv.FormatFloat(FloatS, 'f', 2, 64) + "b", true
	} else if FloatS >= KB && FloatS < MB{
		return strconv.FormatFloat(FloatS/KB, 'f', 2, 64) + "Kb", true
	} else if FloatS >= MB && FloatS <= Max{
		return strconv.FormatFloat(FloatS/MB, 'f', 2, 64) + "Mb", true
	} else{
		return "", false
	}
}

/*
 * Checks if the username and password are valid
**/
func isVerified(user string, password string) bool{
	verification := map[string]string{
		"username": "password",
		"root": "",
	}
	if p, ok := verification[user]; ok{
		return password == p
	}
	return false
}

/*
 * Checks if the user is logged
 **/
func isLogged(t string) (Session, bool){
	for _, s := range sessionController{
		if t == s.Token{
			return s, true
		}
	}
	return Session{"", ""}, false
}

/*
 * Creates the token
 **/
func getToken(userid string) (string, error){
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	signedToken, err := token.SignedString([]byte("qwerty"))
	if err != nil{
		return "", err
	}
	return signedToken, nil
}

/*
 * Releases the token and ends the active session 
**/
func releaseToken(t string) bool{
	for i, s := range sessionController{
		if t == s.Token{
			sessionController[len(sessionController)-1], sessionController[i] = sessionController[i], sessionController[len(sessionController)-1]
			sessionController = sessionController[:len(sessionController)-1]
			break
		}
	}
	for _, s := range sessionController{
		if t == s.Token{
			return false
		}
	}
	return true
}

/*
 * Starts a new session
 **/
func login(write http.ResponseWriter, request *http.Request){
	write.Header().Add("Content-type", "application/json")
	username, password, ok := request.BasicAuth()
    if !ok {
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error, enter a username and password"
		write.Write([]byte(message))
        return
    }
	
	if !isVerified(username, password) {
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error, invalid user or password"
		write.Write([]byte(message))
		return
	}
	
    write.WriteHeader(http.StatusOK)
	token, err := getToken(username)
	if err != nil{
		message := "Error getting token"
		write.Write([]byte(message))
		return
	}
	message := `
{
	"message": "Hi ` + username + ` welcome to the DPIP System"
	"token" "` + token + `"
}
`
    write.Write([]byte(message))
	sessionController = append(sessionController, Session{username, token})
    return
}

/*
 * Ends session
**/
func logout(write http.ResponseWriter, request *http.Request){
	token := request.Header.Get("Authorization")
	if len(token) < 7{
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error, enter your token"
		write.Write([]byte(message))
        return
	}
	token = token[7:]
	session, inUse := isLogged(token)
	if !inUse{
        write.WriteHeader(http.StatusUnauthorized)
        message := "Error, invalid token"
		write.Write([]byte(message))
        return
	}
	revoked := releaseToken(token)
	if !revoked{
		message := "Error, problem revoking token"
		write.Write([]byte(message))
		return
	}
	write.WriteHeader(http.StatusOK)
	message := `
{
	"message": "Bye ` + session.User + `, your token has been revoked"
}
`
	write.Write([]byte(message))
	return
}

/*
 * Uploads the image 
**/
func upload(write http.ResponseWriter, request *http.Request){
	token := request.Header.Get("Authorization")
	if len(token) < 7{
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error, enter your token"
		write.Write([]byte(message))
        return
	}
	token = token[7:]
	_, inUse := isLogged(token)
	if !inUse{
        write.WriteHeader(http.StatusUnauthorized)
        message := "Error, invalid token"
		write.Write([]byte(message))
        return
	}
	write.WriteHeader(http.StatusOK)
	request.ParseMultipartForm(10 << 20)
	_, imgPath, err  := request.FormFile("data")
	if err != nil{
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error while uploading image"
		write.Write([]byte(message))
		return
	}
	size, ok := imgSize(imgPath.Size)
	if !ok{
		message := "Error, image must be under 10 Mb"
		write.Write([]byte(message))
		return
	}
	message := `
{
	"message": "An image has been successfully uploaded"
	"filename": "` + imgPath.Filename + `"
	"size": "` + size + `"
}
`
    write.Write([]byte(message))
	return 
}

/*
 * Gives session status
**/
func status(write http.ResponseWriter, request *http.Request){
	token := request.Header.Get("Authorization")
	if len(token) < 7{
		write.WriteHeader(http.StatusUnauthorized)
		message := "Error, enter your token"
		write.Write([]byte(message))
        return
	}
	token = token[7:]
	session, inUse := isLogged(token)
	if !inUse{
        write.WriteHeader(http.StatusUnauthorized)
        message := "Error, invalid token"
		write.Write([]byte(message))
        return
	}
	write.WriteHeader(http.StatusOK)
	t := time.Now()
	message := `
{
	"message": "Hi ` + session.User + `, the DPIP System is Up and Running "
	"time": "` + t.Format("2006-01-02 15:04:05") + `"
}
`
    write.Write([]byte(message))
    return
}

func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/upload", upload)
	http.HandleFunc("/status", status)
	http.ListenAndServe("localhost:8080", nil)
}