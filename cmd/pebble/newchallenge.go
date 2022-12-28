package main
//we should create a package for the newchallenge.


import (
	"net/http"
	"fmt"

)


//might add ctx Context in the future (to grab account data)
func HandlePQOrder(rw http.ResponseWriter, req *http.Request){
	fmt.Fprint( rw, "Hello Custom World!\n" )
}



