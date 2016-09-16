package simpleauthmysql

import (
	"github.com/jinzhu/gorm"
	"github.com/go-errors/errors"
)

func GetUserByGoogleID(google_id string) *User {
	google_user :=&GoogleUser{}
	if gorm_db == nil {
		panic(errors.New("The DB isn't setup"))
	}
	if err:=gorm_db.Where("google_id = ?", google_id).First(&google_user).Error;err!=nil{
		if err!=gorm.ErrRecordNotFound {
			panic(err)
		}else{
			return nil
		}
	}
	user:=&User{}
	if err:=gorm_db.Where("user_id = ? ", google_user.User_id).First(&user).Error;err!=nil{
		if err!=gorm.ErrRecordNotFound {
			panic(err)
		}else{
			return nil
		}
	}
	return user
}
