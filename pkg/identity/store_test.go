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

package identity

import (
	"errors"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"

	log "github.com/Sirupsen/logrus"
	. "gopkg.in/check.v1"
)

var (
	lbls = labels.Labels{
		"foo":   labels.NewLabel("foo", "bar", labels.LabelSourceContainer),
		"foo2":  labels.NewLabel("foo2", "=bar2", labels.LabelSourceContainer),
		"key":   labels.NewLabel("key", "", labels.LabelSourceContainer),
		`foo\\`: labels.NewLabel(`foo\\`, `\=`, labels.LabelSourceContainer),
		`//`:    labels.NewLabel(`//`, "", labels.LabelSourceContainer),
		`%`:     labels.NewLabel(`%`, `%ed`, labels.LabelSourceContainer),
	}
	lbls2 = labels.Labels{
		"foo":  labels.NewLabel("foo", "bar", labels.LabelSourceContainer),
		"foo2": labels.NewLabel("foo2", "=bar2", labels.LabelSourceContainer),
	}
	wantID = Identity{
		ID: 123,
		Endpoints: map[string]bool{
			"cc08ff400e355f736dce1c291a6a4007ab9f2d56d42e1f3630ba87b861d45307": true,
		},
		Labels: lbls,
	}
	nilAPIError *apierror.APIError
)

func (ds *IdentityTestSuite) TestLabels(c *C) {
	log.SetLevel(log.DebugLevel)
	kvstore.Debug = true

	log.Debugf("Bringing up dummy kvstore setup...")
	err := kvstore.SetupDummy()
	c.Assert(err, IsNil)
	kvstore.Client.DeleteTree(common.OperationalPath)

	InitAllocator(nil)

	//Set up last free ID with zero
	secCtxLbl, new, err := Allocate(lbls, "containerLabel1-1")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = Allocate(lbls, "containerLabel1-2")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = Allocate(lbls2, "containerLabel2-1")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = Allocate(lbls2, "containerLabel2-2")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 2)
	c.Assert(new, Equals, false)

	secCtxLbl, new, err = Allocate(lbls, "containerLabel1-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	//Get labels from ID
	id, err := GetByID(MinimalNumericID)
	c.Assert(err, IsNil)
	wantID.ID = MinimalNumericID
	wantID.Labels = lbls
	c.Assert(id.ID, Equals, wantID.ID)
	c.Assert(id.Labels, DeepEquals, wantID.Labels)
	c.Assert(id.RefCount(), Equals, 3)

	err = Release(lbls, "containerLabel1-1")
	c.Assert(err, IsNil)
	id, err = GetByID(MinimalNumericID)
	c.Assert(err, IsNil)
	wantID.ID = MinimalNumericID
	wantID.Labels = lbls
	c.Assert(id.ID, Equals, wantID.ID)
	c.Assert(id.Labels, DeepEquals, wantID.Labels)
	c.Assert(id.RefCount(), Equals, 2)

	id, err = GetByID(MinimalNumericID + 1)
	c.Assert(err, IsNil)
	wantID.ID = MinimalNumericID + 1
	wantID.Labels = lbls2
	c.Assert(id.ID, Equals, wantID.ID)
	c.Assert(id.Labels, DeepEquals, wantID.Labels)
	c.Assert(id.RefCount(), Equals, 2)

	err = Release(lbls, "containerLabel1-2")
	c.Assert(err, IsNil)
	id, err = GetByID(MinimalNumericID)
	c.Assert(err, IsNil)
	wantID.ID = MinimalNumericID
	wantID.Labels = lbls
	c.Assert(id.ID, Equals, wantID.ID)
	c.Assert(id.Labels, DeepEquals, wantID.Labels)
	c.Assert(id.RefCount(), Equals, 1)

	err = Release(lbls, "containerLabel1-3")
	c.Assert(err, IsNil)

	err = Release(lbls, "containerLabel1-non-existent")
	c.Assert(err, DeepEquals, errors.New("identity not found"))

	secCtxLbl, new, err = Allocate(lbls2, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID+1)
	c.Assert(secCtxLbl.RefCount(), Equals, 3)
	c.Assert(new, Equals, false)

	id, err = GetByLabels(lbls2)
	c.Assert(err, IsNil)
	c.Assert(id, DeepEquals, secCtxLbl)

	err = Release(lbls2, "containerLabel2-1")
	c.Assert(err, IsNil)
	err = Release(lbls2, "containerLabel2-2")
	c.Assert(err, IsNil)
	err = Release(lbls2, "containerLabel2-3")
	c.Assert(err, IsNil)

	secCtxLbl, new, err = Allocate(lbls2, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID+2)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	secCtxLbl, new, err = Allocate(lbls, "containerLabel2-3")
	c.Assert(err, IsNil)
	c.Assert(secCtxLbl.ID, Equals, MinimalNumericID+3)
	c.Assert(secCtxLbl.RefCount(), Equals, 1)
	c.Assert(new, Equals, true)

	log.Debugf("Shutting down testsuite...")
	ShutdownAllocator()
	kvstore.CloseClient()
}
