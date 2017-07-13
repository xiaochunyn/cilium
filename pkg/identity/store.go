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
	"sync"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"

	log "github.com/Sirupsen/logrus"
)

const (
	kvstoreIdentities = common.OperationalPath + "/identities"

	// maxSetOfLabels is the maximum identity identifier to be allocated
	maxSetOfLabels = kvstore.ID(0xFFFF)
)

var (
	allocator  *kvstore.Allocator
	identities = newIdentityCache()
	stopWatch  = make(chan bool, 0)
	allocOwner AllocatorOwner
)

type identityCache struct {
	cache map[string]*Identity
	mutex sync.RWMutex
}

func newIdentityCache() identityCache {
	return identityCache{
		cache: map[string]*Identity{},
	}
}

// AllocatorOwner defines the interface a type owning the allocator must
// implement
type AllocatorOwner interface {
	// OnIdentityChanges is called whenever an identity change has occured
	OnIdentityChanges(typ kvstore.EventType, identity *Identity)
}

// InitAllocator initializes the identity allocator. The passed in owner must
// implement the AllocatorOwner interface. This function should only be called,
// any subsequent calls will be ignored.
func InitAllocator(owner AllocatorOwner) {
	if allocator != nil {
		log.Panicf("Allocator is already initialized")
	}

	a, err := kvstore.NewAllocator(kvstoreIdentities, labels.Labels{},
		kvstore.WithMin(kvstore.ID(MinimalNumericID)),
		kvstore.WithMax(maxSetOfLabels),
		kvstore.WithEvents())
	if err != nil {
		log.Fatalf("Unable to create identity allocator: %s", err)
	}

	startWatcher(a)
	allocator = a
	allocOwner = owner
}

// ShutdownAllocator shuts down the identity allocator
func ShutdownAllocator() {
	if allocator == nil {
		log.Panicf("Shutting down uninitialized allocator")
	}

	stopWatcher()
	allocator.Delete()
	allocator = nil
}

func assignEndpoint(identity *Identity, epid string) {
	identity.mutex.Lock()
	if _, ok := identity.Endpoints[epid]; !ok {
		identity.Endpoints[epid] = true
	}
	identity.mutex.Unlock()
}

func releaseEndpoint(identity *Identity, epid string) (int, error) {
	identity.mutex.Lock()
	if _, ok := identity.Endpoints[epid]; !ok {
		identity.mutex.Unlock()
		return 0, fmt.Errorf("endpoint not found")
	}

	delete(identity.Endpoints, epid)
	remainingEndpoints := len(identity.Endpoints)
	identity.mutex.Unlock()

	return remainingEndpoints, nil
}

// Allocate will retrieve the identity for the specified labels and will
// associated the endpoint ID with the identity
func Allocate(lbls labels.Labels, epid string) (*Identity, bool, error) {
	log.Debugf("Allocating identity for endpoint=%s (labels=%+v)", epid, lbls)

	identities.mutex.RLock()
	// Check the local cache first
	identity, ok := identities.cache[lbls.GetKey()]
	if ok && len(identity.Endpoints) > 0 {
		assignEndpoint(identity, epid)
		identities.mutex.RUnlock()

		log.Debugf("Associated existing identity %d with endpoint %s", identity.ID, epid)
		return identity, false, nil
	}
	identities.mutex.RUnlock()

	id, isNew, err := allocator.Allocate(lbls)
	if err != nil {
		return nil, false, err
	}

	identities.mutex.Lock()
	// Check the local cache first
	identity, ok = identities.cache[lbls.GetKey()]
	if ok && len(identity.Endpoints) > 0 {
		// race condition: another thread inserted the identity while
		// we retrieved it, it is guaranteed to represent the same
		// identity <=> label association so we can simply associate
		// our endpoint with it
		assignEndpoint(identity, epid)
		isNew = false
	} else {
		identity = &Identity{
			ID:        NumericID(id),
			Labels:    lbls,
			Endpoints: map[string]bool{epid: true},
		}

		identities.cache[lbls.GetKey()] = identity
	}
	identities.mutex.Unlock()

	log.Debugf("Associated new identity %d with endpoint %s", identity.ID, epid)
	return identity, isNew, nil
}

func lookupLocalID(id NumericID) *Identity {
	for _, identity := range identities.cache {
		if identity.ID == id {
			return identity
		}
	}

	return nil
}

// GetByID returns the identity matching the specified ID
func GetByID(id NumericID) (*Identity, error) {
	// Step 1: reserved identities
	if id > 0 && id < MinimalNumericID {
		key := id.String()
		lbl := labels.NewLabel(
			key, "", labels.LabelSourceReserved,
		)

		return &Identity{
			ID: id,
			Labels: labels.Labels{
				labels.LabelSourceReserved: lbl,
			},
			Endpoints: map[string]bool{lbl.String(): true},
		}, nil
	}

	// Step 2: Check local cache
	identities.mutex.RLock()
	if identity := lookupLocalID(id); identity != nil {
		identities.mutex.RUnlock()
		return identity, nil
	}
	identities.mutex.RUnlock()

	val, err := allocator.GetByID(kvstore.ID(id))
	if err != nil {
		return nil, err
	}

	lbls, ok := val.(labels.Labels)
	if !ok {
		return nil, fmt.Errorf("value in kvstore not an identity")
	}

	return &Identity{
		ID:        NumericID(id),
		Labels:    lbls,
		Endpoints: map[string]bool{},
	}, nil
}

// GetByLabels returns the identity matching the specified labels
func GetByLabels(lbls labels.Labels) (*Identity, error) {
	identities.mutex.RLock()
	// Check the local cache first
	identity, ok := identities.cache[lbls.GetKey()]
	if ok {
		identities.mutex.RUnlock()
		return identity, nil
	}
	identities.mutex.RUnlock()

	id, err := allocator.Get(lbls)
	if err != nil {
		return nil, err
	}

	return &Identity{
		ID:        NumericID(id),
		Labels:    lbls,
		Endpoints: map[string]bool{},
	}, nil
}

// Release releases the use of an identity by an endpoint
func Release(lbls labels.Labels, epid string) error {
	identities.mutex.Lock()
	// Check the local cache first
	identity, ok := identities.cache[lbls.GetKey()]
	if !ok {
		identities.mutex.Unlock()
		return fmt.Errorf("identity not found")
	}

	rem, err := releaseEndpoint(identity, epid)
	if err != nil {
		identities.mutex.Unlock()
		return err
	}

	log.Debugf("Released identity use by endpoint %s, %d local users remaining", epid, rem)

	if rem == 0 {
		delete(identities.cache, lbls.GetKey())
	}

	identities.mutex.Unlock()

	// After we have reached zero remaining endpoints in the local cache,
	// release the identity in the kvstore
	if rem == 0 {
		log.Debugf("Releasing identity %d in kvstore", identity.ID)
		allocator.Release(lbls)
	}

	return nil
}

func handleAllocatorEvent(event kvstore.AllocatorEvent) {
	eventIdentity := &Identity{
		ID: NumericID(event.ID),
	}

	identities.mutex.Lock()

	switch event.Typ {
	case kvstore.EventTypeCreate, kvstore.EventTypeModify:
		lbls, ok := event.Key.(labels.Labels)
		if !ok {
			log.Warningf("Received invalid event from identity allocator. Invalid type %#v", event)
			return
		}

		identity, ok := identities.cache[lbls.GetKey()]
		if !ok {
			identity = &Identity{
				ID:        NumericID(event.ID),
				Labels:    lbls,
				Endpoints: map[string]bool{},
			}
		} else {
			if kvstore.ID(identity.ID) != event.ID {
				identity.ID = NumericID(event.ID)
				log.Warningf("kvstore inconsistency: received %v event with identity=%d which conflicts with local identity=%d",
					event.Typ, event.ID, identity.ID)
			}
		}

		identities.cache[lbls.GetKey()] = identity
		eventIdentity = identity.DeepCopy()

	case kvstore.EventTypeDelete:
		// always remove on kvstore event but warn on inconsitency
		if identity := lookupLocalID(NumericID(event.ID)); identity != nil {
			if len(identity.Endpoints) >= 0 {
				log.Warningf("Got kvstore deletion event for identity %d with local users",
					event.ID)
			}
			delete(identities.cache, identity.Labels.GetKey())
		}
	}

	identities.mutex.Unlock()

	// Trigger updates in owner
	if allocOwner != nil {
		allocOwner.OnIdentityChanges(event.Typ, eventIdentity)
	}
}

func startWatcher(a *kvstore.Allocator) {
	go func(a *kvstore.Allocator, stop chan bool) {
		for {
			select {
			case <-stop:
				return
			case event := <-a.Events:
				handleAllocatorEvent(event)
			}
		}
	}(a, stopWatch)
}

func stopWatcher() {
	stopWatch <- true
}

// GetIDs returns a slice of all allocated identities
func GetIDs() []NumericID {
	result := make([]NumericID, len(identities.cache))

	identities.mutex.RLock()
	i := 0
	for _, id := range identities.cache {
		result[i] = id.ID
		i++
	}
	identities.mutex.RUnlock()

	return result
}
