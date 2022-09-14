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
	"fmt"
	"io"
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
	NewIntermediate(cn string, opts ...Option) (PKI, error)
	Generate(cn string, opts ...Option) ([]byte, []byte, error)
	Renew(old []byte) (cert []byte, err error)
	CACert() []byte
	CAKey() []byte

	GenerateFromCSR(req *csr.CertificateRequest, profile Profile) (cert, key []byte, err error)
	NewIntermediateFromCSR(csr *csr.CertificateRequest) (PKI, error)

	Save(certPath string, keyPath string) error
}

type pki struct {
	generator *csr.Generator
	signer    signer.Signer

	cert []byte
	key  []byte
}

func New(cn string, opts ...Option) (PKI, error) {
	req := newRequest(cn, opts...)
	if req.Profile != "" {
		return nil, fmt.Errorf("cannot specify profile for root CA")
	}
	return NewFromCSR(req.CertificateRequest)
}

func NewFromReaders(caCert, caKey io.Reader) (PKI, error) {
	cert, err := io.ReadAll(caCert)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	key, err := io.ReadAll(caKey)
	if err != nil {
		return nil, fmt.Errorf("read key: %v", err)
	}
	return NewFromBytes(cert, key)
}

func NewFromCSR(csr *csr.CertificateRequest) (PKI, error) {
	cert, _, key, err := initca.New(csr)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(cert, key)
}

func NewFromFiles(caCert, caKey string) (PKI, error) {
	cert, err := os.ReadFile(caCert)
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(caKey)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(cert, key)
}

func NewFromBytes(cert, key []byte) (PKI, error) {
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

func (p *pki) Generate(cn string, opts ...Option) ([]byte, []byte, error) {
	req := newRequest(cn, opts...)
	if req.Profile == "" {
		req.Profile = ProfileServer
	}
	if req.Profile == ProfileIntermediateCA {
		return nil, nil, fmt.Errorf("profile cannot be intermediate_ca")
	}
	if req.CA != nil {
		return nil, nil, fmt.Errorf("cannot specify CA for leaf certificate")
	}
	return p.GenerateFromCSR(req.CertificateRequest, req.Profile)
}

func (p *pki) GenerateFromCSR(req *csr.CertificateRequest, profile Profile) (cert, key []byte, err error) {
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

func (p *pki) Renew(old []byte) ([]byte, error) {
	cert, err := helpers.ParseCertificatePEM(old)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	req := csr.ExtractCertificateRequest(cert)
	req.Extensions = cert.Extensions
	csrPem, _, err := p.generator.ProcessRequest(req)
	if err != nil {
		return nil, fmt.Errorf("process csr: %w", err)
	}
	return p.signer.Sign(signer.SignRequest{Request: string(csrPem), Profile: ProfileFromCert(cert).String()})
}

func (p *pki) CACert() []byte {
	return p.cert[:]
}

func (p *pki) CAKey() []byte {
	return p.key[:]
}

func (p *pki) NewIntermediate(cn string, opts ...Option) (PKI, error) {
	req := newRequest(cn, opts...)
	if req.Profile != "" && req.Profile != ProfileIntermediateCA {
		return nil, fmt.Errorf("profile must be intermediate_ca")
	}
	return p.NewIntermediateFromCSR(req.CertificateRequest)
}

func (p *pki) NewIntermediateFromCSR(csr *csr.CertificateRequest) (PKI, error) {
	cert, key, err := p.GenerateFromCSR(csr, ProfileIntermediateCA)
	if err != nil {
		return nil, err
	}
	return NewFromBytes(cert, key)
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

type req struct {
	*csr.CertificateRequest
	Profile Profile
}

func newRequest(cn string, opts ...Option) *req {
	req := &req{
		CertificateRequest: &csr.CertificateRequest{
			CN: cn,
			KeyRequest: &csr.KeyRequest{
				A: "rsa",
				S: 2048,
			},
		},
	}
	for _, o := range opts {
		o(req)
	}
	return req
}
