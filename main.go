package main

import (
	"github.com/YudhaBhakti95/belajargolang/model"
	"github.com/YudhaBhakti95/belajargolang/controller"
	"log"
	"net/http"
	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", controller.registerhandler).
		Methods("POST")
	r.HandleFunc("/login", controller.loginhandler).
		Methods("POST")
	r.HandleFunc("/profile", controller.profilehandler).
		Methods("GET")

	log.Fatal(http.ListenAndServe(":8080", r))
}