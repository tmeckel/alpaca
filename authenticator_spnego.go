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
	"fmt"
	"log"
	"net"
	"net/http"

	spnegoprovider "github.com/samuong/alpaca/spnego"
)

//nolint:staticcheck

type spnegoAuthenticator struct {
	/*
	 * Setting the policy to Enabled and entering a nonstandard port (in other words, a port other than 80 or 443) includes it in the generated Kerberos SPN.
	 * Setting the policy to Disabled or leaving it unset means the generated Kerberos SPN won't include a port.
	 */
	enableAuthNegotiatePort bool
}

func (s *spnegoAuthenticator) do(req *http.Request, rt http.RoundTripper, hostname string) (*http.Response, error) {
	provider := spnegoprovider.New()
	if !s.enableAuthNegotiatePort {
		h, _, err := net.SplitHostPort(hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to split host and port from hostname %s, err: %w", hostname, err)
		}
		hostname = h
	}
	log.Printf("SPNEGO hostname: %s", hostname)
	header, err := provider.GetSPNEGOHeader(hostname, req)
	if err != nil {
		return nil, fmt.Errorf("cannot get SPNEGO header: %w", err)
	}

	log.Printf("SPNEGO header: %s", header)
	req.Header.Set("Proxy-Authorization", header)
	return rt.RoundTrip(req)
}
