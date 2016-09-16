package simpleauthmysql

import "time"

type ApiCall struct {
	Api_call_id int64 `gorm:"primary_key" sql:"AUTO_INCREMENT"`
	Created time.Time   `sql:"DEFAULT:current_timestamp"`
	Call_url string `sql:"not null;type:varchar(100)"`
	Cost int16 `sql:"not null"`
	User_id int64 `sql:"not null;index"`
	Api_key_id int64 `sql:"not null;index"`
}

type ApiKey struct {
	Api_key_id int64 `gorm:"primary_key" sql:"AUTO_INCREMENT" json:"api_key_id"`
	Created int64   `sql:"not null" json:"created"`
	Expires int64 ` sql:"not null" json:"expires"`
	Expire_reason string `sql:"type:varchar(100)" json:"expire_reason"`
	Valid bool `sql:"not null;default:1" json:"valid"`
	Owner_id int64 `sql:"not null;index" json:"owner_id"`
	Api_key string `sql:"not null;type:varchar(50);unique_index" json:"api_key"`
}

type ApiKeyMonthLimits struct {
	Month_limit_id int64 `gorm:"primary_key" sql:"AUTO_INCREMENT"`
	User_id int64 `sql:"not null;unique_index"`
	MaxNumberCalls int `sql:"not null"`
	MaxNumRecipes int `sql:"not null"`
	MaxNumSimultaneousParsedIngredients int `sql:"not null"`
}

