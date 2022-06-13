//go:build windows
// +build windows

/*
MIT License

Copyright (c) 2018 Daniel Potapov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package spnego

import (
	"encoding/base64"
	"net/http"

	"github.com/alexbrainman/sspi/negotiate"
)

// SSPI implements spnego.Provider interface on Windows OS
type sspi struct{}

// New constructs OS specific implementation of spnego.Provider interface
func New() Provider {
	return &sspi{}
}

// SetSPNEGOHeader puts the SPNEGO authorization header on HTTP request object
func (s *sspi) SetSPNEGOHeader(req *http.Request) error {
	h, err := canonicalizeHostname(req.URL.Hostname())
	if err != nil {
		return err
	}

	header, err := s.GetSPNEGOHeader(h, req)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", header)
	return nil
}

// GetSPNEGOHeader returns the SPNEGO authorization header
func (s *sspi) GetSPNEGOHeader(hostname string, req *http.Request) (string, error) {
	spn := "HTTP/" + hostname

	cred, err := negotiate.AcquireCurrentUserCredentials()
	if err != nil {
		return "", err
	}
	defer cred.Release()

	secctx, token, err := negotiate.NewClientContext(cred, spn)
	if err != nil {
		return "", err
	}
	defer secctx.Release()

	return "Negotiate " + base64.StdEncoding.EncodeToString(token), nil
}
