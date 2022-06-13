// Copyright 2019, 2021 The Alpaca Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp"
	gospnego "github.com/L11R/go-spnego"
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

type authenticator interface {
	do(req *http.Request, rt http.RoundTripper, hostname string) (*http.Response, error)
}

type ntlmAuthenticator struct {
	domain, username, hash string
}

func (a *ntlmAuthenticator) do(req *http.Request, rt http.RoundTripper, hostname string) (*http.Response, error) {
	negotiate, err := ntlmssp.NewNegotiateMessage(a.domain, hostname)
	if err != nil {
		log.Printf("Error creating NTLM Type 1 (Negotiate) message: %v", err)
		return nil, err
	}
	req.Header.Set("Proxy-Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiate))
	resp, err := rt.RoundTrip(req)
	if err != nil {
		log.Printf("Error sending NTLM Type 1 (Negotiate) request: %v", err)
		return nil, err
	} else if resp.StatusCode != http.StatusProxyAuthRequired {
		log.Printf("Expected response with status 407, got %s", resp.Status)
		return resp, nil
	}
	challenge, err := base64.StdEncoding.DecodeString(
		strings.TrimPrefix(resp.Header.Get("Proxy-Authenticate"), "NTLM "))
	if err != nil {
		log.Printf("Error decoding NTLM Type 2 (Challenge) message: %v", err)
		return nil, err
	}
	authenticate, err := ntlmssp.ProcessChallengeWithHash(challenge, a.username, a.hash)
	if err != nil {
		log.Printf("Error processing NTLM Type 2 (Challenge) message: %v", err)
		return nil, err
	}
	req.Header.Set("Proxy-Authorization",
		"NTLM "+base64.StdEncoding.EncodeToString(authenticate))
	return rt.RoundTrip(req)
}

func (a *ntlmAuthenticator) String() string {
	return fmt.Sprintf("%s@%s:%s", a.username, a.domain, a.hash)
}

// The following two functions are taken from "github.com/Azure/go-ntlmssp". This code was
// copyrighted (2016) by Microsoft and licensed under the MIT License:
// https://github.com/Azure/go-ntlmssp/blob/66371956d46c8e2133a2b72b3d320e435465011f/LICENSE.

// https://github.com/Azure/go-ntlmssp/blob/66371956d46c8e2133a2b72b3d320e435465011f/nlmp.go#L21-L25
func getNtlmHash(password []byte) string {
	hash := md4.New()
	hash.Write(toUnicode(string(password)))
	return hex.EncodeToString(hash.Sum(nil))
}

// https://github.com/Azure/go-ntlmssp/blob/66371956d46c8e2133a2b72b3d320e435465011f/unicode.go#L24-L29
func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints) //nolint:errcheck
	return b.Bytes()
}

type spnegoAuthenticator struct {
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// splitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
func splitHostPort(hostPort string) (host, port string) {
	host = hostPort

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}


func (s *spnegoAuthenticator) do(req *http.Request, rt http.RoundTripper, hostname string) (*http.Response, error) {
	provider := gospnego.New()
	hostname, _ = splitHostPort(hostname)
	log.Printf("SPNEGO hostname: %s", hostname)
	header, err := provider.GetSPNEGOHeader(hostname)
	if err != nil {
		return nil, fmt.Errorf("cannot get SPNEGO header: %w", err)
	}

	log.Printf("SPNEGO header: %s", header)
	req.Header.Set("Proxy-Authorization", header)
	return rt.RoundTrip(req)
}
