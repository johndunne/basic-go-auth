package simpleauthmysql

import (
	"net/http"

	"fmt"
)

func NewHttpAPIError( error_code int, message string ) error{
	return &HttpAPIError{error_code,message,nil}
}
func NewHttpAPIErrorBadRequest( message string ) error {
	return &HttpAPIError{http.StatusBadRequest,message,nil}
}
func NewHttpAPIErrorForbidden( message string ) error {
	return &HttpAPIError{http.StatusForbidden,message,nil}
}
func NewHttpAPIErrorNotAcceptable( message string ) error {
	return &HttpAPIError{http.StatusNotAcceptable,message,nil}
}
func NewHttpAPIErrorUnauthorised( message string ) error {
	return &HttpAPIError{http.StatusUnauthorized,message,nil}
}
func NewHttpAPIErrorNotFound( message string ) error {
	return &HttpAPIError{http.StatusNotFound,message,nil}
}

func NewHttpAPIInternalErrorMessage( error string) error{
	return &HttpAPIError{http.StatusInternalServerError,error,nil}
}

func NewHttpAPIInternalError( error error ) error{
	return &HttpAPIError{http.StatusInternalServerError,"",error}
}

type HttpAPIError struct {
	ErrorCode int `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	ErrorObject error `json:"error"`
}

type HttpAPIResponse struct {
	Message string `json:"message"`
}

func (e HttpAPIError) Error() string {
	return fmt.Sprintf("%s (%d)", e.ErrorMessage, e.ErrorCode)
}