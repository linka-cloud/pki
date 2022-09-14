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
	"crypto/x509"
	"fmt"
)

type Profile string

func (p Profile) Validate() error {
	switch p {
	case ProfileIntermediateCA,
		ProfilePeer,
		ProfileServer,
		ProfileClient:
		return nil
	default:
		return fmt.Errorf("unknown profile: %v", p)
	}
}

func (p Profile) String() string {
	return string(p)
}

const (
	ProfileIntermediateCA Profile = "intermediate_ca"
	ProfilePeer           Profile = "peer"
	ProfileServer         Profile = "server"
	ProfileClient         Profile = "client"
)

func ProfileFromCert(cert *x509.Certificate) Profile {
	var hasClientAuth, hasServerAuth bool
	for _, v := range cert.ExtKeyUsage {
		switch v {
		case x509.ExtKeyUsageClientAuth:
			hasClientAuth = true
		case x509.ExtKeyUsageServerAuth:
			hasServerAuth = true
		}
	}
	if hasClientAuth && hasServerAuth {
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			return ProfileIntermediateCA
		}
		return ProfilePeer
	}
	if hasServerAuth {
		return ProfileServer
	}
	if hasClientAuth {
		return ProfileClient
	}
	return ProfileServer
}

var configJSON = []byte(`
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "intermediate_ca": {
        "usages": [
          "signing",
          "digital signature",
          "key encipherment",
          "cert sign",
          "crl sign",
          "server auth",
          "client auth"
        ],
        "expiry": "8760h",
        "ca_constraint": {
          "is_ca": true,
          "max_path_len": 0,
          "max_path_len_zero": true
        }
      },
      "peer": {
        "usages": [
          "signing",
          "digital signature",
          "key encipherment",
          "client auth",
          "server auth"
        ],
        "expiry": "8760h"
      },
      "server": {
        "usages": [
          "signing",
          "digital signing",
          "key encipherment",
          "server auth"
        ],
        "expiry": "8760h"
      },
      "client": {
        "usages": [
          "signing",
          "digital signature",
          "key encipherment",
          "client auth"
        ],
        "expiry": "8760h"
      }
    }
  }
}
`)
