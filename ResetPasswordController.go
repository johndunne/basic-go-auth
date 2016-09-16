package simpleauthmysql

import (
	"github.com/jinzhu/gorm"
	"time"
	"fmt"
	"net/http"
)

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	if email,present:=MustHaveGetString(w,r,"email");present {
		fmt.Println("Reset password: ", email)
		check_mailbox := "If the email exists, a password reset link will have been sent. Please check your mailbox."
		user := User{}
		if err := gorm_db.Debug().Where("email = ?", email).First(&user).Error; err != nil {
			// TODO Delay response
			if err != gorm.ErrRecordNotFound {
				panic(err)
			}else {
				SendClientErrorBadRequestMessage(w,r,"Email doesn't exist.")
				return
			}
		}

		user_admin := UserAdminAction{}
		if err := gorm_db.Debug().Where("user_id = ?", user.User_id).First(&user_admin).Error; err != nil {
			// TODO Delay response
			if err != gorm.ErrRecordNotFound {
				panic(err)
			} else {
				SendClientErrorBadRequestMessage(w,r,"There's already a password reset to be processed for this user.")
				return
			}
		}

		user_admin.User_id = user.User_id
		user_admin.Created = time.Now().Unix()
		user_admin.RequiresPasswordReset = true
		user_admin.PasswordResetMailSent = 0
		if err := gorm_db.Debug().Save(&user_admin).Error; err != nil {
			panic(err)
		}
		SendClientCreatedOKObject(w,r,check_mailbox)
	}
}