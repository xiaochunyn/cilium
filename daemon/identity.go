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
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/go-openapi/runtime/middleware"
)

type getIdentity struct {
	daemon *Daemon
}

func NewGetIdentityHandler(d *Daemon) GetIdentityHandler {
	return &getIdentity{daemon: d}
}

func (h *getIdentity) Handle(params GetIdentityParams) middleware.Responder {
	lbls := labels.NewLabelsFromModel(params.Labels)
	if id, err := identity.GetByLabels(lbls); err != nil {
		return apierror.Error(GetIdentityUnreachableCode, err)
	} else if id == nil {
		return NewGetIdentityNotFound()
	} else {
		return NewGetIdentityOK().WithPayload(id.GetModel())
	}
}

type getIdentityID struct {
	daemon *Daemon
}

func NewGetIdentityIDHandler(d *Daemon) GetIdentityIDHandler {
	return &getIdentityID{daemon: d}
}

func (h *getIdentityID) Handle(params GetIdentityIDParams) middleware.Responder {
	nid, err := identity.ParseNumericID(params.ID)
	if err != nil {
		return NewGetIdentityIDBadRequest()
	}

	if id, err := identity.GetByID(nid); err != nil {
		return apierror.Error(GetIdentityUnreachableCode, err)
	} else if id == nil {
		return NewGetIdentityIDNotFound()
	} else {
		return NewGetIdentityIDOK().WithPayload(id.GetModel())
	}
}
