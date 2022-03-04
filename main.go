// beeper-media-viewer - A simple web app that can download, decrypt and display encrypted Matrix media.
// Copyright (C) 2022 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"go.mau.fi/mediaviewer/frontend"
)

var defaultHomeserverURL string
var forceDefaultHomeserver bool
var dbURL, dbDriver string
var listenAddress string
var trustForwardHeaders bool
var nodeID int

var fileServer = http.FileServer(http.FS(frontend.FS))
var db *Database

func loadConfig() {
	trustForwardHeaders, _ = strconv.ParseBool(os.Getenv("BMV_TRUST_FORWARD_HEADERS"))
	dbDriver = os.Getenv("BMV_DATABASE_DRIVER")
	dbURL = os.Getenv("BMV_DATABASE_URL")
	if len(dbDriver) == 0 || len(dbURL) == 0 {
		log.Println("BMV_DATABASE_DRIVER or BMV_DATABASE_URL not set, defaulting to sqlite and beeper-media-viewer.db")
		dbDriver = "sqlite3"
		dbURL = "beeper-media-viewer.db"
	}
	listenAddress = os.Getenv("BMV_LISTEN_ADDRESS")
	if len(listenAddress) == 0 {
		listenAddress = ":29333"
	}
	defaultHomeserverURL = os.Getenv("BMV_DEFAULT_HOMESERVER_URL")
	forceDefaultHomeserver, _ = strconv.ParseBool(os.Getenv("BMV_FORCE_DEFAULT_HOMESERVER"))
	nodeIDStr := os.Getenv("BMV_NODE_ID")
	if len(nodeIDStr) > 0 {
		var err error
		nodeID, err = strconv.Atoi(nodeIDStr)
		if err != nil {
			log.Fatalf("Failed to parse node ID '%s': %v", nodeIDStr, err)
		} else if nodeID >= (1 << nodeIDBits) {
			log.Fatalf("Too large node ID %d (maximum is %d)", nodeID, (1<<nodeIDBits)-1)
		}
	} else {
		rand.Seed(time.Now().UnixNano())
		nodeID = rand.Int() & ((1 << nodeIDBits) - 1)
		log.Println("BMV_NODE_ID not set, generated", nodeID)
	}
}

func main() {
	loadConfig()

	dbConn, err := sql.Open(dbDriver, dbURL)
	if err != nil {
		log.Fatalln("Failed to open database:", err)
	}
	db = &Database{dbConn}
	err = db.Upgrade()
	if err != nil {
		log.Fatalln("Failed to upgrade database schema:", err)
	}

	r := mux.NewRouter()
	r.Path("/{fileID:[0-9A-Za-z_-]{11}}").Methods(http.MethodGet).HandlerFunc(serveCustomIndex)
	r.Path("/{fileID:[0-9A-Za-z_-]{11}}/metadata.json").Methods(http.MethodGet).HandlerFunc(serveShortcutMetadata)
	r.Path("/create").Methods(http.MethodPost).HandlerFunc(createShortcut)
	r.PathPrefix("/").Handler(fileServer)

	log.Println("Listening on", listenAddress)
	err = http.ListenAndServe(listenAddress, r)
	if err != nil {
		log.Fatalln("Error in HTTP server:", err)
	}
}

func readUserIP(r *http.Request) string {
	var ip string
	if trustForwardHeaders {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}

func serveCustomIndex(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = "/"
	fileServer.ServeHTTP(w, r)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}

type CreateShortcutResponse struct {
	FileID string `json:"file_id"`
}

func createShortcut(w http.ResponseWriter, r *http.Request) {
	// TODO auth

	var fm FileMetadata
	if err := json.NewDecoder(r.Body).Decode(&fm); err != nil {
		writeError(w, http.StatusBadRequest, "Failed to decode request JSON")
	} else if err = fm.Decode(); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Failed to decode metadata: %v", err))
	} else if err = fm.ResolveHomeserver(); err != nil {
		log.Printf("Failed to resolve homeserver address of %s requested by %s: %v", fm.HomeserverDomain, readUserIP(r), err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to resolve homeserver URL: %v", err))
	} else if shortcut, err := db.CreateShortcut(&fm); err != nil {
		log.Printf("Failed to create shortcut requested by %s: %v", readUserIP(r), err)
		writeError(w, http.StatusInternalServerError, "Failed to create file shortcut")
	} else {
		w.Header().Add("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(CreateShortcutResponse{
			FileID: shortcut,
		})
		if err != nil {
			log.Printf("Failed to encode shortcut create response to %s: %v", readUserIP(r), err)
		}
	}
}

func serveShortcutMetadata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["fileID"]
	shortcut, err := db.FindShortcut(fileID)
	if err != nil {
		log.Printf("Failed to get details of shortcut %s requested by %s", fileID, readUserIP(r))
		writeError(w, http.StatusInternalServerError, "Failed to get file details")
	} else if shortcut == nil {
		writeError(w, http.StatusNotFound, "File not found")
	} else if derivedAuthKey := strings.TrimPrefix(r.Header.Get("Authorization"), "X-Derived-Key "); derivedAuthKey != shortcut.AuthToken {
		writeError(w, http.StatusUnauthorized, "Incorrect authentication key")
	} else {
		w.Header().Add("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(shortcut.GetOutputFormat())
		if err != nil {
			log.Printf("Failed to encode shortcut metadata response to %s: %v", readUserIP(r), err)
		}
	}
}
