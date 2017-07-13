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

package kvstore

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/nodeaddress"

	log "github.com/Sirupsen/logrus"
)

const (
	// maxAllocAttempts is the number of attempted allocation requests
	// performed before failing.
	maxAllocAttempts = 16

	gcInterval = time.Duration(10) * time.Minute
)

// ID is the allocated identifier which maps to a key
type ID uint64

// String returns the string representation of an allocated ID
func (i ID) String() string {
	return strconv.FormatUint(uint64(i), 10)
}

// IDMap provides mapping from ID to key
type IDMap map[ID]AllocatorKey

// Allocator is a distributed ID allocator backed by a KVstore. It maps
// arbitrary keys to identifiers. Multiple users on different cluster nodes can
// in parallel request the ID for keys and are guaranteed to retrieve the same
// ID for an identical key.
//
//
// Key hierarchy
//   slave keys:
//    - basePath/value/key1/node1 => 1001
//    - basePath/value/key1/node2 => 1001
//    - basePath/value/key2/node1 => 1002
//    - basePath/value/key2/node2 => 1002
//
//   master key:
//    - basePath/id/1001 => key1
//    - basePath/id/1002 => key2
type Allocator struct {
	// Events is a channel which will receive AllocatorEvent as IDs are
	// added, modified or removed from the allocator
	Events AllocatorEventChan

	// keyType is the type to be used as allocator key
	keyType AllocatorKey

	cache        IDMap
	validCache   bool
	disableCache bool
	mutex        sync.RWMutex

	// idPrefix is the kvstore key prefix for the master key
	idPrefix string

	// valuePrefix is the kvstore key prefix for the slave keys
	valuePrefix string

	// lockPrefix is the prefix to use to lock the entire distributed
	// allocator for complex operations which are not doable with CAS
	lockPrefix string

	// min is the lower limit when allocating IDs
	min ID

	// max is the upper limit when allocating IDs
	max ID

	// localKeys contains all keys including their reference count for keys
	// which have been allocated and are in local use
	localKeys *localKeys

	// suffix is the suffix attached to keys which must be node specific,
	// this is typical set to the node's IP address
	suffix string

	idWatcherStop chan bool
	stopGC        chan bool
}

// AllocatorOption is the base type for allocator options
type AllocatorOption func(*Allocator)

// NewAllocator creates a new Allocator. Any type can be used as key as long as
// the type implements the AllocatorKey interface. A variable of the type has
// to be passed into NewAllocator() to make the type known.  The specified base
// path is used to prefix all keys in the kvstore. The provided path must be
// unique.
//
// The allocator can be configured by passing in additional options:
//  - WithEvents() - enable Events channel
//  - WithSuffix(string) - customize the node specifix suffix to attach to keys
//  - WithMin(id) - minimum ID to allocate (default: 1)
//  - WithMax(id) - maximum ID to allocate (default max(uint64))
//
// After creation, IDs can be allocated with Allocate() and released with
// Release()
func NewAllocator(basePath string, typ AllocatorKey, opts ...AllocatorOption) (*Allocator, error) {
	if Client == nil {
		return nil, fmt.Errorf("kvstore client not configured")
	}

	a := &Allocator{
		keyType:     typ,
		idPrefix:    basePath + "/id/",
		valuePrefix: basePath + "/value/",
		lockPrefix:  basePath + "/",
		min:         1,
		max:         ID(^uint64(0)),
		localKeys:   newLocalKeys(),
		stopGC:      make(chan bool, 0), // unbuffered channel so gc is stopped in sync
		suffix:      nodeaddress.GetExternalIPv4().String(),
	}

	for _, fn := range opts {
		fn(a)
	}

	a.startGC()

	return a, nil
}

// WithEvents enables AllocatorEvent to be received on Allocator.Events
func WithEvents() AllocatorOption {
	return func(a *Allocator) { a.startWatch() }
}

// WithSuffix sets the suffix of the allocator to the specified value
func WithSuffix(v string) AllocatorOption {
	return func(a *Allocator) { a.suffix = v }
}

// WithMin sets the minimum identifier to be allocated
func WithMin(id ID) AllocatorOption {
	return func(a *Allocator) { a.min = id }
}

// WithMax sets the maximum identifier to be allocated
func WithMax(id ID) AllocatorOption {
	return func(a *Allocator) { a.max = id }
}

// Delete deletes an allocator and stops the garbage collector
func (a *Allocator) Delete() {
	a.stopGC <- true
	a.stopWatch()
}

// DeleteAllKeys will delete all keys
func (a *Allocator) DeleteAllKeys() {
	Client.DeleteTree(a.idPrefix)
	Client.DeleteTree(a.valuePrefix)
	Client.DeleteTree(a.lockPrefix)
}

func invalidKey(key, prefix string, deleteInvalid bool) {
	log.Warningf("kvstore: Found invalid key %s outside of prefix %s. Deleting...", key, prefix)

	if deleteInvalid {
		Delete(key)
	}
}

func (a *Allocator) keyToID(key string, deleteInvalid bool) ID {
	if !strings.HasPrefix(key, a.idPrefix) {
		invalidKey(key, a.idPrefix, deleteInvalid)
		return 0
	}

	id, _ := strconv.ParseUint(key[len(a.idPrefix):], 10, 64)
	return ID(id)
}

// Naive ID allocation mechanism.
// FIXME: This should consider a random ID in the future
func (a *Allocator) selectAvailableID() (ID, string) {
	for id := a.min; id <= a.max; id++ {
		if _, ok := a.cache[id]; !ok {
			return id, id.String()
		}
	}

	return 0, ""
}

// RefillCache invalidates and refills the local cache. Afterwards,
// Allocator.Cache will contain entries for all IDs to key mappings as found in
// the KVstore.
func (a *Allocator) RefillCache() error {
	// fetch all /id/ keys
	ids, err := ListPrefix(a.idPrefix)
	if err != nil {
		return err
	}

	newCache := IDMap{}
	for k, v := range ids {
		if id := a.keyToID(k, true); id != 0 {
			key, err := a.keyType.PutKey(string(v))
			if err == nil {
				newCache[id] = key
			}
		}
	}

	a.mutex.Lock()
	a.cache = newCache
	if !a.disableCache {
		a.validCache = true
	}
	a.mutex.Unlock()

	return nil
}

func (a *Allocator) allocate(key AllocatorKey, k []byte) (ID, error) {
	a.mutex.RLock()
	if !a.validCache {
		// unlock for the duration of the cache refresh
		a.mutex.RUnlock()

		if err := a.RefillCache(); err != nil {
			return 0, err
		}

		a.mutex.RLock()
	}

	id, strID := a.selectAvailableID()
	a.mutex.RUnlock()
	if id == 0 {
		return 0, fmt.Errorf("no more identifiers available")
	}

	trace("selected available key %d", id)

	// create /id/<ID> and fail if it already exists
	err := CreateOnly(a.idPrefix+strID, k, false)
	if err == nil {
		// Add it to local cache
		a.mutex.Lock()
		a.cache[id] = key
		a.mutex.Unlock()

		// return allocated ID as JSON
		return id, nil
	}

	// Creation failed. Another agent most likely beat us to allocting this
	// ID. Retry and also mark cache as invalid
	a.mutex.Lock()
	a.validCache = false
	a.mutex.Unlock()

	return 0, fmt.Errorf("CAS operation failed: %s", err)
}

func (a *Allocator) createValueNodeKey(key string, newID ID) error {
	newIDjson, err := json.Marshal(newID)
	if err != nil {
		return fmt.Errorf("unable to marshal value: %s", err)
	}

	// add a new key /value/<key>/<node> to account for the reference
	// The key is protected with a TTL/lease and will expire after LeaseTTL
	masterKey := a.idPrefix + newID.String()
	valueKey := a.valuePrefix + key + "/" + a.suffix
	if err := CreateIfExists(masterKey, valueKey, newIDjson, true); err != nil {
		return err
	}

	a.localKeys.allocate(key, newID)

	return nil
}

// AllocatorKey is the interface to implement in order for a type to be used as
// key for the allocator
type AllocatorKey interface {
	GetKey() string
	PutKey(v string) (AllocatorKey, error)
	String() string
}

// Allocate will retrieve the ID for the provided key. If no ID has been
// allocated for this key yet, a key will be allocated. If allocation fails,
// most likely due to a parallel allocation of the same ID by another user,
// allocation is re-attempted for maxAllocAttempts times.
//
// Returns the ID allocated to the key, if the ID had to be allocated, then
// true is returned. An error is returned in case of failure.
func (a *Allocator) Allocate(key AllocatorKey) (ID, bool, error) {
	var (
		err   error
		value ID
		k     = key.GetKey()
	)

	// Check our list of local keys already in use and increment the refcnt
	val := a.localKeys.get(k)
	if val != nil {
		id, ok := val.(ID)
		if !ok {
			a.localKeys.release(k)
			return 0, false, fmt.Errorf("BUG: invalid type returned from localKeys")
		}

		trace("Allocate %s -> reusing local id %d", key, id)
		return id, false, nil
	}

	trace("Allocate %s", key)

	for attempt := 0; attempt < maxAllocAttempts; attempt++ {
		isNew := false

		// fetch first key that matches /value/<key> while ignoring the
		// node suffix
		if value, err = a.Get(key); err != nil {
			return 0, false, err
		}

		if value == 0 {
			// allocate a new ID and store the valueKey in it
			if value, err = a.allocate(key, []byte(k)); err != nil {
				continue
			}

			isNew = true
		}

		if err = a.createValueNodeKey(k, value); err != nil {
			continue
		}

		return value, isNew, nil
	}

	return 0, false, fmt.Errorf("max allocation attempts reached, last error: %s", err)
}

// Get returns the ID which is allocate to a key. Returns an ID of 0 if no ID
// has been allocated to this key yet.
func (a *Allocator) Get(key AllocatorKey) (ID, error) {
	value, err := GetPrefix(a.valuePrefix + key.GetKey())
	trace("AllocateGet %s -> %v (err=%v)", key, value, err)
	if err != nil || value == nil {
		return 0, err
	}

	newID := ID(0)
	if err = json.Unmarshal(value, &newID); err != nil {
		return 0, fmt.Errorf("unable to unmarshal value: %s", err)
	}

	return newID, nil
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (a *Allocator) GetByID(id ID) (AllocatorKey, error) {
	a.mutex.RLock()
	if a.validCache {
		if v, ok := a.cache[id]; ok {
			a.mutex.RUnlock()
			return v, nil
		}
	}
	a.mutex.RUnlock()

	v, err := Get(a.idPrefix + id.String())
	if err != nil {
		return nil, err
	}

	return a.keyType.PutKey(string(v))
}

// Release releases the use of an ID associated with the provided key. After
// the last user has released the ID, the key is removed in the KVstore.
func (a *Allocator) Release(key AllocatorKey) {
	k := key.GetKey()
	// release the key locally, if it was the last use, remove the node
	// specific value key to remove the global reference mark
	if a.localKeys.release(k) {
		valueKey := a.valuePrefix + k + "/" + a.suffix
		if err := Delete(valueKey); err != nil {
			log.Warningf("ignoring node specific ID key %s deletion error: %s", key, err)
		}

		// FIXME: etcd 3.3 will make it possible to do a lockless
		// cleanup of the ID and release it right away. For now we rely
		// on the GC to kick in a release unused IDs.
	}
}

func (a *Allocator) runGC() error {
	lock, err := Client.LockPath(a.lockPrefix)
	if err != nil {
		return fmt.Errorf("lock failed: %s", err)
	}
	defer lock.Unlock()

	// fetch list of all /id/ keys
	allocated, err := ListPrefix(a.idPrefix)
	if err != nil {
		return fmt.Errorf("list failed: %s", err)
	}

	// iterate over /id/
	for key, v := range allocated {
		// fetch list of all /value/<key> keys
		uses, err := ListPrefix(a.valuePrefix + string(v))
		if err != nil {
			continue
		}

		// if ID has no user, delete it
		if len(uses) == 0 {
			Delete(key)
		}
	}

	a.RefillCache()

	return nil
}

func (a *Allocator) startGC() {
	go func(a *Allocator) {
		for {
			if err := a.runGC(); err != nil {
				log.Debugf("unable to run id-alloc gc on prefix %s: %s", a.idPrefix, err)
			}

			select {
			case <-a.stopGC:
				log.Debugf("Stopped gc")
				return
			case <-time.After(gcInterval):
			}

		}
	}(a)
}

// AllocatorEventChan is a channel to receive allocator events on
type AllocatorEventChan chan AllocatorEvent

// AllocatorEvent is an event sent over AllocatorEventChan
type AllocatorEvent struct {
	// Typ is the type of event (create / modify / delete)
	Typ EventType

	// ID is the allocated ID
	ID ID

	// Key is the key associated with the ID
	Key AllocatorKey
}

func (a *Allocator) startWatch() {
	a.Events = make(AllocatorEventChan, 1024)
	a.idWatcherStop = make(chan bool, 0)

	go func(a *Allocator) {
		watcher := StartWatch(a.idPrefix, a.idPrefix, 512)
		for {
			select {
			case event := <-watcher.Events:
				if id := a.keyToID(event.Key, true); id != 0 {
					a.mutex.Lock()

					var key AllocatorKey

					if len(event.Value) > 0 {
						var err error
						key, err = a.keyType.PutKey(string(event.Value))
						if err != nil {
							log.Warningf("Unable to unmarshal allocator key: %s", err)
						}
					}

					switch event.Typ {
					case EventTypeCreate, EventTypeModify:
						a.cache[id] = key
					case EventTypeDelete:
						delete(a.cache, id)
					}
					a.mutex.Unlock()

					a.Events <- AllocatorEvent{
						Typ: event.Typ,
						ID:  ID(id),
						Key: key,
					}
				}

			case <-a.idWatcherStop:
				watcher.Stop()
				return
			}
		}
	}(a)
}

func (a *Allocator) stopWatch() {
	if a.Events != nil {
		close(a.Events)
		a.idWatcherStop <- true
		close(a.idWatcherStop)
	}
}
