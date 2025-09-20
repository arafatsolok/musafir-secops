package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/musafir/controller/handlers"
	"github.com/musafir/controller/middleware"
)

func main() {
	// Create router
	r := mux.NewRouter()

	// Add middleware
	r.Use(middleware.CORS)
	r.Use(middleware.Logging)

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.HandleFunc("/threats", handlers.GetThreats).Methods("GET")
	api.HandleFunc("/threats", handlers.CreateThreat).Methods("POST")
	api.HandleFunc("/threats/{id}", handlers.GetThreat).Methods("GET")
	api.HandleFunc("/threats/{id}", handlers.UpdateThreat).Methods("PUT")
	api.HandleFunc("/threats/{id}", handlers.DeleteThreat).Methods("DELETE")
	
	api.HandleFunc("/threat-feeds", handlers.GetThreatFeeds).Methods("GET")
	api.HandleFunc("/threat-feeds", handlers.CreateThreatFeed).Methods("POST")
	api.HandleFunc("/threat-feeds/{id}", handlers.GetThreatFeed).Methods("GET")
	api.HandleFunc("/threat-feeds/{id}", handlers.UpdateThreatFeed).Methods("PUT")
	api.HandleFunc("/threat-feeds/{id}", handlers.DeleteThreatFeed).Methods("DELETE")
	
	api.HandleFunc("/ioc", handlers.GetIOCs).Methods("GET")
	api.HandleFunc("/ioc", handlers.CreateIOC).Methods("POST")
	api.HandleFunc("/ioc/{id}", handlers.GetIOC).Methods("GET")
	api.HandleFunc("/ioc/{id}", handlers.UpdateIOC).Methods("PUT")
	api.HandleFunc("/ioc/{id}", handlers.DeleteIOC).Methods("DELETE")

	api.HandleFunc("/statistics", handlers.GetStatistics).Methods("GET")

	// Web routes
	r.HandleFunc("/", handlers.Dashboard).Methods("GET")
	r.HandleFunc("/threats", handlers.ThreatsPage).Methods("GET")
	r.HandleFunc("/threat-feeds", handlers.ThreatFeedsPage).Methods("GET")
	r.HandleFunc("/ioc", handlers.IOCPage).Methods("GET")
	r.HandleFunc("/statistics", handlers.StatisticsPage).Methods("GET")

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}