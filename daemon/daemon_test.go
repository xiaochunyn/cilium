// Copyright 2016-2017 Authors of Cilium
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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *Daemon
}

var _ = Suite(&DaemonSuite{})

func (ds *DaemonSuite) SetUpTest(c *C) {
	tempRunDir, err := ioutil.TempDir("", "cilium-test-run")
	c.Assert(err, IsNil)
	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	c.Assert(err, IsNil)

	daemonConf := &Config{
		DryMode: true,
		Opts:    option.NewBoolOptions(&options.Library),
	}
	daemonConf.RunDir = tempRunDir
	daemonConf.StateDir = tempRunDir
	daemonConf.DockerEndpoint = "tcp://127.0.0.1"
	daemonConf.ValidLabelPrefixes = nil
	daemonConf.Opts.Set(endpoint.OptionDropNotify, true)
	daemonConf.Device = "undefined"

	err = kvstore.SetupDummy()
	c.Assert(err, IsNil)

	d, err := NewDaemon(daemonConf)
	c.Assert(err, IsNil)
	ds.d = d
	kvstore.Client.DeleteTree(common.OperationalPath)
}

func (ds *DaemonSuite) TearDownTest(c *C) {
	identity.ShutdownAllocator()
	os.RemoveAll(ds.d.conf.RunDir)
}
