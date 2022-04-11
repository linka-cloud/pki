// Copyright 2021 Linka Cloud  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pki

import (
	"os"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	DefaultAlgo = "rsa"
	DefaultSize = 2048
)

type PKI interface {
	Generate(req *csr.CertificateRequest, profile Profile) (cert, key []byte, err error)
	CACert() []byte
	CAKey() []byte
	NewIntermediate(csr *csr.CertificateRequest) (PKI, error)
	Save(certPath string, keyPath string) error
}

type pki struct {
	generator *csr.Generator
	signer    signer.Signer

	cert []byte
	key  []byte
}

func NewPKIFromCSR(csr *csr.CertificateRequest) (PKI, error) {
	cert, _, key, err := initca.New(csr)
	if err != nil {
		return nil, err
	}
	return NewPKIFromBytes(cert, key)
}

func NewPKIFromFiles(caCert, caKey string) (PKI, error) {
	cert, err := os.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(caKey)
	if err != nil {
		return nil, err
	}
	return NewPKIFromBytes(cert, key)
}

func NewPKIFromBytes(cert, key []byte) (PKI, error) {
	parsedCa, err := helpers.ParseCertificatePEM(cert)
	if err != nil {
		return nil, err
	}
	priv, err := helpers.ParsePrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	c, err := config.LoadConfig(configJSON)
	if err != nil {
		return nil, err
	}
	s, err := local.NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), c.Signing)
	if err != nil {
		return nil, err
	}
	g := &csr.Generator{Validator: genkey.Validator}
	return &pki{signer: s, generator: g, cert: cert, key: key}, nil
}

func (p *pki) Generate(req *csr.CertificateRequest, profile Profile) (cert, key []byte, err error) {
	if err := profile.Validate(); err != nil {
		return nil, nil, err
	}
	if req.KeyRequest == nil {
		req.KeyRequest = &csr.KeyRequest{
			A: DefaultAlgo,
			S: DefaultSize,
		}
	}
	csrPEM, key, err := p.generator.ProcessRequest(req)
	if err != nil {
		return nil, nil, err
	}
	signReq := signer.SignRequest{Request: string(csrPEM), Profile: string(profile)}
	cert, err = p.signer.Sign(signReq)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func (p *pki) CACert() []byte {
	return p.cert[:]
}

func (p *pki) CAKey() []byte {
	return p.key[:]
}

func (p *pki) NewIntermediate(csr *csr.CertificateRequest) (PKI, error) {
	cert, key, err := p.Generate(csr, ProfileIntermediateCA)
	if err != nil {
		return nil, err
	}
	return NewPKIFromBytes(cert, key)
}

func (p *pki) Save(certPath string, keyPath string) error {
	return Save(certPath, p.CACert(), keyPath, p.CAKey())
}

func Save(certPath string, cert []byte, keyPath string, key []byte) error {
	if err := os.WriteFile(certPath, cert, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return err
	}
	return nil
}

func NewRequest(cn string, opts ...Option) *csr.CertificateRequest {
	req := &csr.CertificateRequest{
		CN: cn,
	}
	for _, o := range opts {
		o(req)
	}
	return req
}
