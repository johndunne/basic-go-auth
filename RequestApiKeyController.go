// @SubApi API managment [/request-apikey]
package simpleauthmysql

import (
	"github.com/astaxie/beego"
	"net/http"
)

type RequestApiKeyController struct {
	beego.Controller
}

func (this *RequestApiKeyController) Get() {
	////this.TplNames = "index.tpl"
}

func (this *RequestApiKeyController) Post() {
	//id := this.Input().Get("id")
	//intid, err := strconv.Atoi(id)
}

func (this *RequestApiKeyController) Put() {
}

func (this *RequestApiKeyController) Delete() {
}

// @Title RequestApiKey
// @Description Get an API key
// @Accept  json
// @Param   search         path    string     true         "Food ID"
// @Success 200 {object} ApiKey
// @Failure 400 {object} simpleauthmysql.HttpAPIError    Customer ID must be specified
// @Resource /request-apikey
// @Router /request-apikey    [get]
func RequestApiKey(w http.ResponseWriter, r *http.Request) {
	if logged_in_user_id := GetAuthenticatedUser(r);logged_in_user_id>0 {
		if logged_in_user_id == 0 {
			SendClientErrorUnauthorizedResult(w, r, "Sign in first.")
		}else {
			apiKeyUniqueIDFetcherChan <- logged_in_user_id
			new_api_key := <-apiKeyFetcherChan
			SendClientCreatedOKObject(w, r, new_api_key)
		}
	}else {
		SendClientErrorUnauthorizedResult(w, r, "Please signin")
	}
}
