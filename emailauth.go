package simpleauthmysql

import (
	"github.com/hjr265/postmark.go/postmark"
	"net/mail"
	"net/smtp"
	"fmt"
	"bytes"
	"html/template"
	"github.com/go-errors/errors"
	"strings"
)

var auth smtp.Auth
var postmark_client *postmark.Client

func testSendDefault() {
	templateData := struct {
		Name string
		URL  string
	}{
		Name: "Dhanush",
		URL:  "http://geektrust.in",
	}
	r := NewDefaultRequest("", "dhanush@geektrust.in", "password", "smtp.gmail.com", "admin@alldunne.com",[]string{"junk@junk.com"}, "Hello Junk!", "Hello, World!")
	err := r.ParseTemplate("views/emails/forgot_password.tpl", templateData)
	if err != nil {
		ok, _ := r.SendEmail()
		fmt.Println(ok)
	}
}

func TestSendPostmark() {
	templateData := struct {
		Name string
		URL  string
	}{
		Name: "Dhanush",
		URL:  "http://geektrust.in",
	}
	r := NewPostmarkRequest("cd1ee9f2-3766-4dff-8179-2e62559ca217", "40097c81-dadf-4142-84a0-23fa20434f11","monitor@alldunne.org", []string{"john@alldunne.com"}, "Hello Junk!", "Hello, World!")
	err := r.ParseTemplate("views/emails/forgot_password.tpl", templateData)
	if err != nil {
		panic(err)
	}else{
		if ok, err := r.SendEmail();err!=nil{
			fmt.Println(ok)
			panic(err)
		}else{
			fmt.Println(ok)
		}
	}
}

func SendPostMarkEmail(){
	templateData := struct {
		Name string
		URL  string
	}{
		Name: "Dhanush",
		URL:  "http://geektrust.in",
	}
	r := NewPostmarkRequest("cd1ee9f2-3766-4dff-8179-2e62559ca217", "40097c81-dadf-4142-84a0-23fa20434f11","monitor@alldunne.org", []string{"john@alldunne.com"}, "Hello Junk!", "Hello, World!")
	err := r.ParseTemplate("views/emails/forgot_password.tpl", templateData)
	if err != nil {
		panic(err)
	}else{
		if ok, err := r.SendEmail();err!=nil{
			fmt.Println(ok)
			panic(err)
		}else{
			fmt.Println(ok)
		}
	}

}
var DEFAULT_SMTP = 1
var POSTMARK_SMTP = 2

//Request struct
type emailRequest struct {
	from    string
	to      []string
	subject string
	body    string
	provider int
}

type Email struct {
	From    string
	To      []string
	Subject string
	BodyData map[string]string
}

func SetupPostmarkAuth(server_api_token, account_api_token string){
	if len(server_api_token)==0{
		panic(errors.New("Invalid postmark server api token."))
	}
	if len(account_api_token)==0{
		panic(errors.New("Invalid postmark account api token."))
	}
	postmark_client = &postmark.Client{
		ApiKey: server_api_token,
		Secure: true,
	}
}

func NewPostmarkRequest(server_api_token, account_api_token, from string, to []string, subject, body string) *emailRequest {
	//postmark_client = postmark.NewClient(server_api_token, account_api_token)
	postmark_client = &postmark.Client{
		ApiKey: server_api_token,
		Secure: true,
	}
	return &emailRequest{
		to:      to,
		subject: subject,
		from: from,
		body:    body,
		provider: POSTMARK_SMTP,
	}
}

func NewDefaultRequest(identity, smtp_username, smtp_password, smtp_host, from string, to []string, subject, body string) *emailRequest {
	auth = smtp.PlainAuth(identity, smtp_username, smtp_password, smtp_host)
	return &emailRequest{
		to:      to,
		subject: subject,
		body:    body,
		provider: DEFAULT_SMTP,
	}
}

func SendEmail(email Email, template_filename string) (bool, error) {
	fmt.Println("Sending email")
	email_request := &emailRequest{
		to:      email.To,
		subject: email.Subject,
		from: email.From,
		provider: POSTMARK_SMTP,
	}
	if e:=email_request.ParseTemplate(template_filename, email.BodyData); e!=nil{
		return false, e
	}
	return email_request.SendEmail()
}

func (r *emailRequest) SendEmail() (bool, error) {
	switch r.provider {
	case DEFAULT_SMTP:
		return r.sendEmailViaDefault()
	case POSTMARK_SMTP:
		return r.sendEmailViaPostmark()
	default:
		panic(errors.New("Unknown email provider"))
	}
}

func (r *emailRequest) sendEmailViaPostmark() (bool, error) {
	res, err := postmark_client.Send(&postmark.Message{
		From: &mail.Address{
			Name:    r.from,
			Address: r.from,
		},
		To: []*mail.Address{
			{
				Name:    "John Dunne",
				Address: r.to[0],
			},
		},
		Subject:  r.subject,
		TextBody: strings.NewReader(r.body),
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", res)
	return true, nil
}

/*func (r *Request) sendEmailViaPostmark() (bool, error) {
	email := postmark.Email{
		From: r.from,
		To: r.to,
		Subject: r.subject,
		HtmlBody: "...",
		TextBody: "...",
		Tag: "pw-reset",
		TrackOpens: true,
	}

	if _, err := postmark_client.SendEmail(email); err!=nil {
		return false, err
	}
	return true, nil
}*/

func (r *emailRequest) sendEmailViaDefault() (bool, error) {
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"
	subject := "Subject: " + r.subject + "!\n"
	msg := []byte(subject + mime + "\n" + r.body)
	addr := "smtp.gmail.com:587"

	if err := smtp.SendMail(addr, auth, "dhanush@geektrust.in", r.to, msg); err != nil {
		return false, err
	}
	return true, nil
}

func (r *emailRequest) ParseTemplate(templateFileName string, data interface{}) error {
	t, err := template.ParseFiles(templateFileName)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err = t.Execute(buf, data); err != nil {
		return err
	}
	r.body = buf.String()
	return nil
}