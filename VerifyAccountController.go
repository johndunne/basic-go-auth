package simpleauthmysql

import (
	"github.com/jinzhu/gorm"
	"net/http"
)

func VerifyAccountSignup(w http.ResponseWriter, r *http.Request) {
	//c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())

	if code,present:=MustHaveGetString(w,r,"code");present {
		email := User{}
		if err := gorm_db.Debug().Where("verify_code = ?", code).First(&email).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				panic(err)
			}else{
				SendClientErrorBadRequestMessage(w,r,"Code doesn't exist.")
				return
			}
		}

		if len(email.VerifyCode) == 0 {
			SendClientErrorBadRequestMessage(w,r,"Already verified.")
		} else {
			if err := gorm_db.Debug().Exec("UPDATE user SET verify_code = NULL WHERE user_id = ?", email.User_id).Error; err != nil {
				panic(err)
			}
			SendClientCreatedOKObject(w,r,"Signup completed")
		}
	}
}