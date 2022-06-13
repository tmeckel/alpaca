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
	"net"
	"net/http"
	"strings"
)

// Provider is the interface that wraps OS agnostic functions for handling SPNEGO communication
type Provider interface {
	SetSPNEGOHeader(*http.Request) error
	GetSPNEGOHeader(hostname string, req *http.Request) (string, error)
}

func canonicalizeHostname(hostname string) (string, error) {
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", err
	}
	if len(addrs) < 1 {
		return hostname, nil
	}

	names, err := net.LookupAddr(addrs[0])
	if err != nil {
		return "", err
	}
	if len(names) < 1 {
		return hostname, nil
	}

	return strings.TrimRight(names[0], "."), nil
}
