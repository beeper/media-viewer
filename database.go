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
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

type Database struct {
	*sql.DB
}

type upgrade func(*sql.Tx) error

var upgrades = []upgrade{
	func(tx *sql.Tx) error { return nil },
	func(tx *sql.Tx) error {
		_, err := tx.Exec("DROP TABLE IF EXISTS shortcut")
		if err != nil {
			return err
		}
		_, err = tx.Exec(`CREATE TABLE shortcut (
			shortcut   TEXT  PRIMARY KEY,
			homeserver TEXT  NOT NULL,
			auth_token bytea NOT NULL,
			ciphertext bytea NOT NULL
		)`)
		return err
	},
}

func (db *Database) upgradeTo(ver int) (err error) {
	var tx *sql.Tx
	defer func() {
		if tx != nil && err != nil {
			err = tx.Rollback()
			log.Println("Failed to rollback after errored upgrade:", err)
		}
	}()
	if tx, err = db.Begin(); err != nil {
		err = fmt.Errorf("failed to begin upgrade transaction: %w", err)
	} else if err = upgrades[ver-1](tx); err != nil {
		err = fmt.Errorf("failed to upgrade to v%d: %w", ver, err)
	} else if _, err = tx.Exec("DELETE FROM version"); err != nil {
		err = fmt.Errorf("failed to delete old version number from database: %w", err)
	} else if _, err = tx.Exec("INSERT INTO version (version) VALUES ($1)", ver); err != nil {
		err = fmt.Errorf("failed to update version in database: %w", err)
	} else if err = tx.Commit(); err != nil {
		err = fmt.Errorf("failed to commit upgrade to v%d: %w", ver, err)
	}
	return
}

func (db *Database) Upgrade() error {
	var ver int
	if _, err := db.Exec("CREATE TABLE IF NOT EXISTS version (version INTEGER PRIMARY KEY)"); err != nil {
		return fmt.Errorf("failed to create version table: %w", err)
	} else if err = db.QueryRow("SELECT version FROM version").Scan(&ver); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to query current version: %w", err)
	} else if ver == len(upgrades) {
		return nil // db is up-to-date
	} else if ver > len(upgrades) {
		return fmt.Errorf("unsupported database schema version v%d", ver)
	}

	for ; ver < len(upgrades); ver++ {
		log.Printf("Upgrading database from v%d to v%d\n", ver, ver+1)
		err := db.upgradeTo(ver + 1)
		if err != nil {
			return err
		}
	}
	return nil
}

var shortcutCounter uint32

const counterBits = 14
const timestampBits = 40
const nodeIDBits = 64 - timestampBits - counterBits

func makeSnowflakeishID() string {
	var shortcut [8]byte
	ts := time.Now().Unix()

	// 40 bits of timestamp
	shortcut[0] = byte(ts >> 32)
	shortcut[1] = byte(ts >> 24)
	shortcut[2] = byte(ts >> 16)
	shortcut[3] = byte(ts >> 8)
	shortcut[4] = byte(ts)

	// Counter: 14 bits at the end
	counter := atomic.AddUint32(&shortcutCounter, 1) & ((1 << counterBits) - 1)
	// Node ID: 10 bits between timestamp and counter
	counter |= uint32(nodeID) << counterBits

	shortcut[5] = byte(counter >> 16)
	shortcut[6] = byte(counter >> 8)
	shortcut[7] = byte(counter)
	return base64.RawURLEncoding.EncodeToString(shortcut[:])
}

const (
	insertShortcutQuery = "INSERT INTO shortcut (shortcut, homeserver, auth_token, ciphertext) VALUES ($1, $2, $3, $4)"
	findShortcutQuery   = "SELECT homeserver, auth_token, ciphertext FROM shortcut WHERE shortcut=$1"
)

func (db *Database) CreateShortcut(metadata *FileMetadata) (string, error) {
	if !metadata.decoded {
		return "", fmt.Errorf("file metadata has not been decoded")
	}
	shortcut := makeSnowflakeishID()
	_, err := db.Exec(
		insertShortcutQuery,
		shortcut, metadata.HomeserverURL, metadata.authTokenBytes, metadata.ciphertextBytes,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert shortcut: %w", err)
	}
	return shortcut, err
}

func (db *Database) FindShortcut(shortcut string) (*FileMetadata, error) {
	var fm FileMetadata
	err := db.
		QueryRow(findShortcutQuery, shortcut).
		Scan(&fm.HomeserverURL, &fm.authTokenBytes, &fm.ciphertextBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	fm.decoded = true
	fm.AuthToken = base64.RawStdEncoding.EncodeToString(fm.authTokenBytes)
	fm.Ciphertext = base64.RawStdEncoding.EncodeToString(fm.ciphertextBytes)
	return &fm, nil
}
