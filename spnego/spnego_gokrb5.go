//go:build !windows
// +build !windows

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
	"net/http"
	"os"
	"os/user"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

type krb5 struct {
	cfg *config.Config
	cl  *client.Client
}

// New constructs OS specific implementation of spnego.Provider interface
func New() Provider {
	return &krb5{}
}

func (k *krb5) makeCfg() error {
	if k.cfg != nil {
		return nil
	}

	cfgPath := os.Getenv("KRB5_CONFIG")
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = "/etc/krb5.conf" // ToDo: Macs and Windows have different path, also some Unix may have /etc/krb5/krb5.conf
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	k.cfg = cfg
	return nil
}

func (k *krb5) makeClient() error {
	u, err := user.Current()
	if err != nil {
		return err
	}

	ccpath := "/tmp/krb5cc_" + u.Uid

	ccname := os.Getenv("KRB5CCNAME")
	if strings.HasPrefix(ccname, "FILE:") {
		ccpath = strings.SplitN(ccname, ":", 2)[1]
	}

	ccache, err := credentials.LoadCCache(ccpath)
	if err != nil {
		return err
	}

	k.cl, err = client.NewFromCCache(ccache, k.cfg, client.DisablePAFXFAST(true))
	return err
}

func (k *krb5) SetSPNEGOHeader(req *http.Request) error {
	h, err := canonicalizeHostname(req.URL.Hostname())
	if err != nil {
		return err
	}

	header, err := k.GetSPNEGOHeader(h, req)
	if err != nil {
		return err
	}

	req.Header.Set(spnego.HTTPHeaderAuthRequest, header)
	return nil
}

func (k *krb5) GetSPNEGOHeader(hostname string, req *http.Request) (string, error) {
	if err := k.makeCfg(); err != nil {
		return "", err
	}

	if err := k.makeClient(); err != nil {
		return "", err
	}

	if err := spnego.SetSPNEGOHeader(k.cl, req, "HTTP/"+hostname); err != nil {
		return "", err
	}

	return req.Header.Get(spnego.HTTPHeaderAuthRequest), nil
}
