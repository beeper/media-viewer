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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"
)

type FileMetadata struct {
	MXC       string `json:"url"`
	SHA256    string `json:"sha256"`
	IV        string `json:"iv"`
	Key       string `json:"key,omitempty"`
	KeySHA256 string `json:"key_sha256,omitempty"`
	Signature string `json:"signature"`

	HomeserverURL string `json:"homeserver_url"`

	Info map[string]interface{} `json:"info"`

	sha256Bytes    []byte
	ivBytes        []byte
	keySHA256Bytes []byte
	signatureBytes []byte
	infoBytes      []byte
	decoded        bool
}

func (fm FileMetadata) GetOutputFormat() FileMetadata {
	fm.KeySHA256 = ""
	return fm
}

var contentURIRegex = regexp.MustCompile("^mxc://(.+?)/(.+)$")
var serverNameRegex = regexp.MustCompile(`^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9A-Fa-f:.]{2,45}]|[A-Za-z0-9-.]{1,255})(:\d{1,5})?$`)

func (fm *FileMetadata) Decode() error {
	if parts := contentURIRegex.FindStringSubmatch(fm.MXC); parts == nil {
		return fmt.Errorf("invalid Matrix content URI")
	} else if !serverNameRegex.MatchString(parts[1]) {
		return fmt.Errorf("invalid Matrix server name")
	}

	var err error
	fm.sha256Bytes, err = base64.RawStdEncoding.DecodeString(fm.SHA256)
	if err != nil {
		return fmt.Errorf("invalid base64 in sha256 field: %w", err)
	}
	fm.ivBytes, err = base64.RawStdEncoding.DecodeString(fm.IV)
	if err != nil {
		return fmt.Errorf("invalid base64 in iv field: %w", err)
	}
	if len(fm.Key) > 0 {
		var keyBytes []byte
		keyBytes, err = base64.RawURLEncoding.DecodeString(fm.Key)
		fm.Key = ""
		if err != nil {
			return fmt.Errorf("invalid base64 in key field: %w", err)
		}
		h := hmac.New(sha256.New, keyBytes)
		h.Write([]byte(fm.MXC + fm.SHA256 + fm.IV))
		fm.Signature = base64.RawStdEncoding.EncodeToString(h.Sum(nil))
		keySHA := sha256.Sum256(keyBytes)
		fm.KeySHA256 = base64.RawStdEncoding.EncodeToString(keySHA[:])
	}
	fm.keySHA256Bytes, err = base64.RawStdEncoding.DecodeString(fm.KeySHA256)
	if err != nil {
		return fmt.Errorf("invalid base64 in key_sha256 field: %w", err)
	}
	fm.signatureBytes, err = base64.RawStdEncoding.DecodeString(fm.Signature)
	if err != nil {
		return fmt.Errorf("invalid base64 in signature field: %w", err)
	}
	fm.infoBytes, err = json.Marshal(fm.Info)
	if err != nil {
		return fmt.Errorf("failed to marshal info JSON: %w", err)
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
	}

	parts := contentURIRegex.FindStringSubmatch(fm.MXC)
	if parts == nil {
		return fmt.Errorf("invalid Matrix content URI")
	}
	serverName := parts[1]
	wellKnownCacheLock.Lock()
	defer wellKnownCacheLock.Unlock()
	if cached, ok := wellKnownCache[serverName]; ok && cached.FetchedAt.Add(wellKnownCacheTime).After(time.Now()) {
		fm.HomeserverURL = cached.Homeserver.BaseURL
		return nil
	}

	url := fmt.Sprintf("https://%s/.well-known/matrix/client", serverName)
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
		wellKnownCache[serverName] = respData
		fm.HomeserverURL = respData.Homeserver.BaseURL
		return nil
	}
}
