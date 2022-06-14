// Copyright 2019, 2021, 2022 The Alpaca Authors
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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/samuong/alpaca/cancelable"
)

var tlsClientConfig *tls.Config

type ProxyHandler struct {
	transport *http.Transport
	auth      authenticator
	block     func(string)
}

type proxyFunc func(*http.Request) (*url.URL, error)

func NewProxyHandler(auth authenticator, proxy proxyFunc, block func(string)) ProxyHandler {
	tr := &http.Transport{Proxy: proxy, TLSClientConfig: tlsClientConfig}
	return ProxyHandler{tr, auth, block}
}

func (ph ProxyHandler) WrapHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Pass CONNECT requests and absolute-form URIs to the ProxyHandler.
		// If the request URL has a scheme, it is an absolute-form URI
		// (RFC 7230 Section 5.3.2).
		if req.Method == http.MethodConnect || req.URL.Scheme != "" {
			ph.ServeHTTP(w, req)
			return
		}
		// The request URI is an origin-form or asterisk-form target which we
		// handle as an origin server (RFC 7230 5.3). authority-form URIs
		// are only for CONNECT, which has already been dispatched to the
		// ProxyHandler.
		next.ServeHTTP(w, req)
	})
}

func (ph ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	deleteRequestHeaders(req)
	if req.Method == http.MethodConnect {
		ph.handleConnect(w, req)
	} else {
		ph.proxyRequest(w, req, ph.auth)
	}
}

func (ph ProxyHandler) handleConnect(w http.ResponseWriter, req *http.Request) {
	// Establish a connection to the server, or an upstream proxy.
	id := req.Context().Value(contextKeyID)
	proxy, err := ph.transport.Proxy(req)
	if err != nil {
		log.Printf("[%d] Error finding proxy for request: %v", id, err)
	}
	var server net.Conn
	if proxy == nil {
		server, err = ph.connectDirect(req)
	} else {
		server, err = ph.connectViaProxy(req, proxy, ph.auth)
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "proxyconnect" {
			log.Printf("[%d] Temporarily blocking proxy: %q", id, proxy.Host)
			ph.block(proxy.Host)
		}
	}
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	serverCloser := cancelable.NewCloser(server)
	defer serverCloser.Close()
	// Take over the connection back to the client by hijacking the ResponseWriter.
	h, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("[%d] Error hijacking response writer", id)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	client, _, err := h.Hijack()
	if err != nil {
		log.Printf("[%d] Error hijacking connection: %v", id, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	clientCloser := cancelable.NewCloser(client)
	defer clientCloser.Close()
	// Write the response directly to the client connection. If we use Go's ResponseWriter, it
	// will automatically insert a Content-Length header, which is not allowed in a 2xx CONNECT
	// response (see https://tools.ietf.org/html/rfc7231#section-4.3.6).
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    req.ProtoMajor,
		ProtoMinor:    req.ProtoMinor,
		ContentLength: -1,
	}
	if err := resp.Write(client); err != nil {
		log.Printf("[%d] Error writing response: %v", id, err)
		return
	}
	// Kick off goroutines to copy data in each direction. Whichever goroutine finishes first
	// will close the Reader for the other goroutine, forcing any blocked copy to unblock. This
	// prevents any goroutine from blocking indefinitely (which will leak a file descriptor).
	serverCloser.Cancel()
	clientCloser.Cancel()
	go func() { _, _ = io.Copy(server, client); server.Close() }()
	go func() { _, _ = io.Copy(client, server); client.Close() }()
}

func (ph ProxyHandler) connectDirect(req *http.Request) (net.Conn, error) {
	server, err := net.Dial("tcp", req.Host)
	if err != nil {
		id := req.Context().Value(contextKeyID)
		log.Printf("[%d] Error dialling host %s: %v", id, req.Host, err)
	}
	return server, err
}

func (ph ProxyHandler) connectViaProxy(req *http.Request, proxy *url.URL, auth authenticator) (net.Conn, error) {
	id := req.Context().Value(contextKeyID)
	var tr transport
	defer tr.Close()
	if err := tr.dial(proxy); err != nil {
		log.Printf("[%d] Error dialling proxy %s: %v", id, proxy.Host, err)
		return nil, err
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		log.Printf("[%d] Error reading CONNECT response: %v", id, err)
		return nil, err
	} else if resp.StatusCode == http.StatusProxyAuthRequired && auth != nil {
		log.Printf("[%d] Got %q response, retrying with auth", id, resp.Status)
		resp.Body.Close()
		if err := tr.dial(proxy); err != nil {
			log.Printf("[%d] Error re-dialling %s: %v", id, proxy.Host, err)
			return nil, err
		}
		resp, err = auth.do(req, &tr, proxy.Host)
		if err != nil {
			return nil, err
		}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("[%d] Unexpected response status: %s", id, resp.Status)
	}
	return tr.hijack(), nil
}

func (ph ProxyHandler) proxyRequest(w http.ResponseWriter, req *http.Request, auth authenticator) {
	id := req.Context().Value(contextKeyID)
	proxy, err := ph.transport.Proxy(req)
	if err != nil {
		log.Printf("Failed to get Proxy for qreuest [%d] : %v", id, err)
		return
	}

	var resp *http.Response
	if proxy == nil || auth == nil {
		resp, err = ph.transport.RoundTrip(req)
	} else {
		resp, err = auth.do(req, ph.transport, proxy.Host)
	}

	if err != nil {
		log.Printf("[%d] Error forwarding request: %v", id, err)
		w.WriteHeader(http.StatusBadGateway)
		var oe *net.OpError
		if errors.As(err, &oe) && oe.Op == "proxyconnect" {
			proxy, err := ph.transport.Proxy(req)
			if err != nil {
				log.Printf("[%d] Proxy connect error to unknown proxy: %v", id, err)
				return
			}
			log.Printf("[%d] Temporarily blocking proxy: %q", id, proxy.Host)
			ph.block(proxy.Host)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		log.Printf("[%d] Got %q response", id, resp.Status)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		// The response status has already been sent, so if copying fails, we can't return
		// an error status to the client.  Instead, log the error.
		log.Printf("[%d] Error copying response body: %v", id, err)
		return
	}
}

func deleteConnectionTokens(header http.Header) {
	// Remove any header field(s) with the same name as a connection token (see
	// https://tools.ietf.org/html/rfc2616#section-14.10)
	if values, ok := header["Connection"]; ok {
		for _, value := range values {
			if value == "close" {
				continue
			}
			tokens := strings.Split(value, ",")
			for _, token := range tokens {
				header.Del(strings.TrimSpace(token))
			}
		}
	}
}

func deleteRequestHeaders(req *http.Request) {
	// Delete hop-by-hop headers (see https://tools.ietf.org/html/rfc2616#section-13.5.1)
	deleteConnectionTokens(req.Header)
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("TE")
	req.Header.Del("Upgrade")
}

func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	// Delete hop-by-hop headers (see https://tools.ietf.org/html/rfc2616#section-13.5.1)
	deleteConnectionTokens(w.Header())
	w.Header().Del("Connection")
	w.Header().Del("Keep-Alive")
	w.Header().Del("Proxy-Authenticate")
	w.Header().Del("Trailer")
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Upgrade")
}
