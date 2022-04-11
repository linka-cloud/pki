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
	"io"

	"github.com/cloudflare/cfssl/log"
	"github.com/sirupsen/logrus"
)

var l *logger

type logger struct {
	l logrus.FieldLogger
}

func (l *logger) Info(s string) {
	l.l.Info(s)
}
func (l *logger) Warning(s string) {
	l.l.Warning(s)
}
func (l *logger) Debug(s string) {
	l.l.Debug(s)
}
func (l *logger) Err(s string) {
	l.l.Error(s)
}
func (l *logger) Crit(s string) {
	l.l.Fatal(s)
}
func (l *logger) Emerg(s string) {
	l.l.Fatal(s)
}

func SetLogger(fieldLogger logrus.FieldLogger) {
	l.l = fieldLogger
}

func init() {
	ll := logrus.New()
	ll.SetOutput(io.Discard)
	l = &logger{l: ll}
	log.SetLogger(l)
}
