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

package main

import (
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/csr"
	"github.com/sirupsen/logrus"

	pki2 "go.linka.cloud/pki"
)

var (
	etcdNodes = [][]string{
		{"etcd-0", "10.10.10.10", "etcd-0.internal.example.org", "localhost", "127.0.0.1"},
		{"etcd-1", "10.10.10.11", "etcd-1.internal.example.org", "localhost", "127.0.0.1"},
		{"etcd-2", "10.10.10.12", "etcd-2.internal.example.org", "localhost", "127.0.0.1"},
	}
)

func main() {
	caPKI, err := pki2.New("Example Org Root CA")
	if err != nil {
		logrus.Fatal(err)
	}
	if err := os.MkdirAll("tests", os.ModePerm); err != nil {
		logrus.Fatal(err)
	}
	if err := caPKI.Save("tests/ca.crt", "tests/ca.key"); err != nil {
		logrus.Fatal(err)
	}
	pki, err := caPKI.NewIntermediate("Example Org ETCD CA", pki2.WithCA(&csr.CAConfig{Expiry: "42720h"}))
	if err != nil {
		logrus.Fatal(err)
	}
	if err := pki.Save("tests/etcd-ca.crt", "tests/etcd-ca.key"); err != nil {
		logrus.Fatal(err)
	}
	for _, v := range etcdNodes {
		cert, key, err := pki.Generate(v[0], pki2.WithHosts(v...), pki2.WithProfile(pki2.ProfilePeer))
		if err != nil {
			logrus.Fatal(err)
		}
		cert, err = pki.Renew(cert)
		if err != nil {
			logrus.Fatal(err)
		}
		cert = append(cert, pki.CACert()...)
		if err := pki2.Save(fmt.Sprintf("tests/%s.crt", v[0]), cert, fmt.Sprintf("tests/%s.key", v[0]), key); err != nil {
			logrus.Fatal(err)
		}
	}
}
