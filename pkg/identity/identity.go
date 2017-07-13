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
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	secLabelTimeout = time.Duration(120 * time.Second)

	// MinimalNumericID represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericID = NumericID(256)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericID(0)
)

// NumericID represents an identity of an entity to which consumer policy
// can be applied to.
type NumericID uint32

// IdentityMap maps identities to identities
type IdentityMap map[NumericID][]NumericID

// ParseNumericID parses an identity from a string
func ParseNumericID(id string) (NumericID, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericID(0), err
	}
	return NumericID(nid), nil
}

func (id NumericID) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericID) String() string {
	if v, exists := ReservedIdentityNames[id]; exists {
		return v
	}

	return id.StringID()
}

// Uint32 normalizes the ID for use in BPF program.
func (id NumericID) Uint32() uint32 {
	return uint32(id)
}

type identityEndpointsMap map[string]bool

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// ID is the identifier given by the allocator
	ID NumericID

	// Labels which describes this identity
	Labels labels.Labels

	// Endpoints is map of all endpoints which use this identity
	Endpoints identityEndpointsMap
	mutex     sync.RWMutex
}

func NewIdentityFromModel(base *models.Identity) *Identity {
	if base == nil {
		return nil
	}

	id := &Identity{
		ID:        NumericID(base.ID),
		Labels:    make(labels.Labels),
		Endpoints: identityEndpointsMap{},
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels[lbl.Key] = lbl
	}

	return id
}

func (id *Identity) GetModel() *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:     int64(id.ID),
		Labels: []string{},
	}

	for _, v := range id.Labels {
		ret.Labels = append(ret.Labels, v.String())
	}

	return ret
}

// String returns the identity identifier in human readable form
func (id *Identity) String() string {
	return fmt.Sprintf("%d", id.ID)
}

func (id *Identity) DeepCopy() *Identity {
	cpy := &Identity{
		ID:        id.ID,
		Labels:    id.Labels.DeepCopy(),
		Endpoints: make(identityEndpointsMap, len(id.Endpoints)),
	}
	for k, v := range id.Endpoints {
		cpy.Endpoints[k] = v
	}
	return cpy
}

// NewIdentity creates a new identity
func NewIdentity(id NumericID, lbls labels.Labels, endpoints []string) *Identity {
	identity := &Identity{
		ID:        id,
		Endpoints: identityEndpointsMap{},
		Labels:    lbls,
	}

	for _, v := range endpoints {
		identity.Endpoints[v] = true
	}

	return identity
}

// RefCount returns the number of endpoints using the identity
func (id *Identity) RefCount() int {
	return len(id.Endpoints)
}

const (
	ID_UNKNOWN NumericID = iota
	ID_HOST
	ID_WORLD
)

var (
	ReservedIdentities = map[string]NumericID{
		labels.IDNameHost:  ID_HOST,
		labels.IDNameWorld: ID_WORLD,
	}
	ReservedIdentityNames = map[NumericID]string{
		ID_HOST:  labels.IDNameHost,
		ID_WORLD: labels.IDNameWorld,
	}
)

func GetReservedID(name string) NumericID {
	if v, ok := ReservedIdentities[name]; ok {
		return v
	}
	return ID_UNKNOWN
}
