package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/sessions"
	_ "golang.org/x/net/context"
	"golang.org/x/oauth2"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

const (
	redirectURI string = "http://localhost:8080/callback"
)

// Authentication + Encryption key pairs
var sessionStoreKeyPairs = [][]byte{
	[]byte("something-very-secret"),
	nil,
}

var store sessions.Store

var (
	clientID     string
	clientSecret string
	tenantId     string
	authUrl      string
	tokenUrl     string
	config       *oauth2.Config
	ctx          context.Context
)

type User struct {
	Email       string
	DisplayName string
}

func init() {
	// Create file system store with no size limit
	fsStore := sessions.NewFilesystemStore("/tmp", sessionStoreKeyPairs...)
	fsStore.MaxLength(0)
	store = fsStore

	gob.Register(&User{})
	gob.Register(&oauth2.Token{})
}

func main() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	ctx = context.Background()
	clientID = "<Azure AD app client ID>"
	clientSecret = "<Azure AD app client Secret>"
	tenantId = "<Azure AD TenantID>"

	authUrl = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/authorize?resource=https://graph.windows.net", tenantId)
	tokenUrl = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantId)

	config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Endpoint: oauth2.Endpoint{
			AuthURL: authUrl,
			TokenURL: tokenUrl,
		},

		Scopes: []string{"profile"},
	}

	http.Handle("/", handle(IndexHandler))
	http.Handle("/callback", handle(CallbackHandler))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

type handle func(w http.ResponseWriter, req *http.Request) error

func (h handle) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Handler panic: %v", r)
		}
	}()
	if err := h(w, req); err != nil {
		log.Printf("Handler error: %v", err)

		if httpErr, ok := err.(Error); ok {
			http.Error(w, httpErr.Message, httpErr.Code)
		}
	}
}

type Error struct {
	Code    int
	Message string
}

func (e Error) Error() string {
	if e.Message == "" {
		e.Message = http.StatusText(e.Code)
	}
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func IndexHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")

	var token *oauth2.Token
	if req.FormValue("logout") != "" {
		session.Values["token"] = nil
		sessions.Save(req, w)
	} else {
		if v, ok := session.Values["token"]; ok {
			token = v.(*oauth2.Token)
		}
	}

	var data = struct {
		Token   *oauth2.Token
		AuthURL string
	}{
		Token:   token,
		AuthURL: config.AuthCodeURL(SessionState(session), oauth2.AccessTypeOnline),
	}

	return indexTempl.Execute(w, &data)
}

var indexTempl = template.Must(template.New("").Parse(`<!DOCTYPE html>
<html>
  <head>
    <title>Azure AD OAuth2 Example</title>

    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
  </head>
  <body class="container-fluid">
    <div class="row">
      <div class="col-xs-4 col-xs-offset-4">
        <h1>Azure AD OAuth2 Example</h1>
{{with .Token}}
        <div id="displayName"></div>
        <a href="/?logout=true">Logout</a>
{{else}}
        <a href="{{$.AuthURL}}">Login</a>
{{end}}
      </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
    <script>
{{with .Token}}
      var token = {{.}};

      $.ajax({
        url: 'https://graph.windows.net/me?api-version=1.6',
        dataType: 'json',
        success: function(data, status) {
        	$('#displayName').text('Welcome ' + data.displayName);
        },
        beforeSend: function(xhr, settings) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + token.access_token);
        }
      });
{{end}}
    </script>
  </body>
</html>
`))

/**
Method to handle OAuth callback, not library specific
*/
func CallbackHandler(w http.ResponseWriter, req *http.Request) error {
	session, _ := store.Get(req, "session")
	queryParts, _ := url.ParseQuery(req.URL.RawQuery)

	// Use the authorization code that is pushed to the redirect
	// URL.
	code := queryParts["code"][0]
	log.Printf("code: %s\n", code)

	// Exchange will do the handshake to retrieve the initial access token.
	token, err := config.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %s", token)
	// The HTTP Client returned by conf.Client will refresh the token as necessary.
	client := config.Client(ctx, token)

	getUserInfo(client)

	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("Authentication successful")
	}

	session.Values["token"] = &token
	if err := sessions.Save(req, w); err != nil {
		return fmt.Errorf("error saving session: %v", err)
	}

	http.Redirect(w, req, "/", http.StatusFound)
	return nil

}

func getUserInfo(client *http.Client) {

	resp, err := client.Get("https://graph.windows.net/me?api-version=1.6")
	if err != nil {
		log.Printf("Error creating token  %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("token response was %s", resp.Status)
		return
	}

	var userinfo interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		log.Printf("error decoding JSON response: %v", err)
		return
	}

	log.Printf("userInfo : %v", userinfo)

}

func SessionState(session *sessions.Session) string {
	return base64.StdEncoding.EncodeToString(sha256.New().Sum([]byte(session.ID)))
}

func dump(v interface{}) {
	spew.Dump(v)
}
