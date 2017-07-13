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
	"sync"
)

type localKey struct {
	val    interface{}
	refcnt uint64
}

type localKeyMap map[string]*localKey

// localKeys is a map of keys in use locally. Keys can be used multiple times.
// A refcnt is managed to know when a key is no longer in use
type localKeys struct {
	keys  localKeyMap
	mutex sync.Mutex
}

func newLocalKeys() *localKeys {
	return &localKeys{keys: localKeyMap{}}
}

// allocate creates an entry for key in localKeys if needed and increments the
// refcnt. The value associated with the key is returned
func (lk *localKeys) allocate(key string, val interface{}) interface{} {
	lk.mutex.Lock()
	defer lk.mutex.Unlock()

	if k, ok := lk.keys[key]; ok {
		k.refcnt++
		return k.val
	}

	lk.keys[key] = &localKey{val: val, refcnt: 1}
	return val
}

// get returns the value associated with the key and increments the refcnt
func (lk *localKeys) get(key string) interface{} {
	lk.mutex.Lock()
	defer lk.mutex.Unlock()

	if k, ok := lk.keys[key]; ok {
		k.refcnt++
		return k.val
	}

	return nil
}

// release releases the refcnt of a key. When the last reference was released,
// the key is deleted
func (lk *localKeys) release(key string) bool {
	lk.mutex.Lock()
	if k, ok := lk.keys[key]; ok {
		k.refcnt--
		if k.refcnt == 0 {
			delete(lk.keys, key)
			lk.mutex.Unlock()
			return true
		}
	}
	lk.mutex.Unlock()

	return false
}
