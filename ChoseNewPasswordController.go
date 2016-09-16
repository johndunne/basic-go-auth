package simpleauthmysql

import (
	"github.com/jinzhu/gorm"
	"net/http"
)

func ChoosePassword(w http.ResponseWriter, r *http.Request) {
	//c.Data["xsrfdata"] = template.HTML(c.XSRFFormHTML())
	var user_to_change *User
	if new_password, password_present := MustHaveGetString(w,r, "password"); password_present {
		if code, code_present := MightHaveGetString(r , "code"); code_present {
			user := UserAdminAction{}
			if err := gorm_db.Debug().Where("reset_code = ?", code).First(&user).Error; err != nil {
				if err != gorm.ErrRecordNotFound {
					panic(err)
				}
				// TODO Make sure code's arent allowed to be used for too long
				SendClientErrorBadRequestMessage(w, r, "Invalid reset code.")
				return
			}
			p, present := GetUserByUserid(user.User_id)
			if present == false {
				panic(NewHttpAPIInternalErrorMessage("Invalid user object"))
			}
			user_to_change = p
		} else {
			// There's no code, so if the password is to be changed, then authority is required.
			signed_in_user := GetAuthenticatedUser(r)
			if signed_in_user == 0 {
				signed_in_user = GetAuthorisedUserID(r)
			}
			if signed_in_user == 0 {
				panic(NewHttpAPIErrorUnauthorised("Please signin before changing the password. Otherwise, user the reset password endpoint."))
			}
			p, present := GetUserByUserid(signed_in_user)
			if present == false {
				panic(NewHttpAPIInternalErrorMessage("Invalid user object"))
			}
			user_to_change = p
		}
		if user_to_change.User_id == 0 {
			panic(NewHttpAPIInternalErrorMessage("Unable to load the user object"))
		}
		// Comparing the password with the hash
		//err = bcrypt.CompareHashAndPassword(hashedPassword, password_bytes)
		//fmt.Println(err) // nil means it is a match
		hashed_password := User{}.BcryptHashForPassword(new_password)

		tx := gorm_db.Begin()
		if err := tx.Exec("UPDATE user SET password = ? WHERE user_id = ?", string(hashed_password), user_to_change.User_id).Error; err != nil {
			tx.Rollback()
			panic(err)
		}

		if err := tx.Exec("DELETE FROM user_admin_action WHERE user_id = ?", user_to_change.User_id).Error; err != nil {
			tx.Rollback()
			panic(err)
			return
		}
		tx.Commit()
		SendClientCreatedOKObject(w, r, "New password is set.")
	}
}