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
	"github.com/cloudflare/cfssl/csr"
)

type Option func(r *req)

func WithNames(names ...csr.Name) Option {
	return func(r *req) {
		r.Names = append(r.Names, names...)
	}
}

func WithHosts(hosts ...string) Option {
	return func(r *req) {
		r.Hosts = append(r.Hosts, hosts...)
	}
}

func WithKeyRequest(kr *csr.KeyRequest) Option {
	return func(r *req) {
		r.KeyRequest = kr
	}
}

func WithProfile(p Profile) Option {
	return func(r *req) {
		r.Profile = p
	}
}

func WithCA(ca *csr.CAConfig) Option {
	return func(r *req) {
		r.CA = ca
	}
}
