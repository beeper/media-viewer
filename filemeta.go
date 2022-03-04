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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type FileMetadata struct {
	AuthToken  string `json:"auth_token"`
	Ciphertext string `json:"ciphertext"`

	HomeserverDomain string `json:"homeserver,omitempty"`
	HomeserverURL    string `json:"homeserver_url"`

	authTokenBytes  []byte
	ciphertextBytes []byte
	decoded         bool
}

func (fm FileMetadata) GetOutputFormat() FileMetadata {
	fm.HomeserverDomain = ""
	fm.AuthToken = ""
	return fm
}

var serverNameRegex = regexp.MustCompile(`^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9A-Fa-f:.]{2,45}]|[A-Za-z0-9-.]{1,255})(:\d{1,5})?$`)

func (fm *FileMetadata) Decode() error {
	if len(fm.HomeserverDomain) > 0 && !serverNameRegex.MatchString(fm.HomeserverDomain) {
		return fmt.Errorf("invalid Matrix server name")
	}

	var err error
	fm.authTokenBytes, err = base64.RawStdEncoding.DecodeString(fm.AuthToken)
	if err != nil {
		return fmt.Errorf("invalid base64 in auth_token field: %w", err)
	}
	fm.ciphertextBytes, err = base64.RawStdEncoding.DecodeString(fm.Ciphertext)
	if err != nil {
		return fmt.Errorf("invalid base64 in ciphertext field: %w", err)
	}
	fm.decoded = true
	return nil
}

type WellKnownResponse struct {
	Homeserver struct {
		BaseURL string `json:"base_url"`
	} `json:"m.homeserver"`
	FetchedAt time.Time `json:"-"`
}

var wellKnownCache = make(map[string]WellKnownResponse)
var wellKnownCacheLock sync.Mutex

const wellKnownCacheTime = 24 * time.Hour

func (fm *FileMetadata) ResolveHomeserver() error {
	if !forceDefaultHomeserver && len(fm.HomeserverURL) > 0 {
		return nil
	} else if len(defaultHomeserverURL) > 0 {
		fm.HomeserverURL = defaultHomeserverURL
		return nil
	} else if len(fm.HomeserverDomain) == 0 {
		return fmt.Errorf("no homeserver provided")
	}

	wellKnownCacheLock.Lock()
	defer wellKnownCacheLock.Unlock()
	if cached, ok := wellKnownCache[fm.HomeserverDomain]; ok && cached.FetchedAt.Add(wellKnownCacheTime).After(time.Now()) {
		fm.HomeserverURL = cached.Homeserver.BaseURL
		return nil
	}

	overrideURL, found := os.LookupEnv("BMV_CLIENT_API_OVERRIDE_" + strings.ReplaceAll(strings.ToUpper(fm.HomeserverDomain), ".", "_"))
	if found {
		fm.HomeserverURL = overrideURL
		var resp WellKnownResponse
		resp.Homeserver.BaseURL = overrideURL
		resp.FetchedAt = time.Now()
		wellKnownCache[fm.HomeserverDomain] = resp
		return nil
	}

	url := fmt.Sprintf("https://%s/.well-known/matrix/client", fm.HomeserverDomain)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var respData WellKnownResponse
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); err != nil {
		return fmt.Errorf("failed to prepare .well-known request: %w", err)
	} else if resp, err := http.DefaultClient.Do(req); err != nil {
		return fmt.Errorf("failed to make .well-known request: %w", err)
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("invalid .well-known response: HTTP %d", resp.StatusCode)
	} else if err = json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("invalid .well-known response: body is not JSON")
	} else if len(respData.Homeserver.BaseURL) == 0 {
		return fmt.Errorf("invalid .well-known response: missing homeserver base URL")
	} else {
		respData.FetchedAt = time.Now()
		wellKnownCache[fm.HomeserverDomain] = respData
		fm.HomeserverURL = respData.Homeserver.BaseURL
		return nil
	}
}
