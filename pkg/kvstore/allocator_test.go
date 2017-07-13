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
	"fmt"

	log "github.com/Sirupsen/logrus"
	. "gopkg.in/check.v1"
)

type AllocatorSuite struct{}

var _ = Suite(&AllocatorSuite{})

type TestType string

func (t TestType) GetKey() string { return string(t) }
func (t TestType) String() string { return string(t) }
func (t TestType) PutKey(v string) (AllocatorKey, error) {
	return TestType(v), nil
}

func (s *AllocatorSuite) SetUpTest(c *C) {
	log.SetLevel(log.DebugLevel)

	err := SetupDummy()
	c.Assert(err, IsNil)
}

func (s *AllocatorSuite) TearDownTest(c *C) {
	CloseClient()
}

func (s *AllocatorSuite) TestSelectID(c *C) {
	minID, maxID := ID(1), ID(5)
	a := Allocator{keyType: TestType(""), min: minID, max: maxID}
	a.cache = IDMap{}

	// allocate all available IDs
	for i := minID; i <= maxID; i++ {
		id, val := a.selectAvailableID()
		c.Assert(id, Equals, ID(i))
		c.Assert(val, Equals, i.String())
		a.cache[id] = TestType(fmt.Sprintf("key-%d", i))
	}

	// we should be out of IDs
	id, val := a.selectAvailableID()
	c.Assert(id, Equals, ID(0))
	c.Assert(val, Equals, "")
}

func (s *AllocatorSuite) TestAllocate(c *C) {
	maxID := ID(256)
	allocator, err := NewAllocator("cilium-unittest", TestType(""), WithMax(maxID), WithSuffix("a"))
	c.Assert(err, IsNil)
	c.Assert(allocator, Not(IsNil))

	// remove any keys which might be leftover
	allocator.DeleteAllKeys()

	// refresh local cache and check size
	err = allocator.RefillCache()
	c.Assert(err, IsNil)
	c.Assert(len(allocator.cache), Equals, 0)

	// allocate all available IDs
	for i := ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator.Allocate(key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, true)

		// refcnt must be 1
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))
	}

	// we should be out of id space here
	_, new, err := allocator.Allocate(TestType(fmt.Sprintf("key%04d", maxID+1)))
	c.Assert(err, Not(IsNil))
	c.Assert(new, Equals, false)

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator.Allocate(key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)

		// refcnt must now be 2
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(2))
	}

	// Create a 2nd allocator, refill it
	allocator2, err := NewAllocator("cilium-unittest", TestType(""), WithMax(maxID), WithSuffix("b"))
	c.Assert(err, IsNil)
	c.Assert(allocator2, Not(IsNil))

	err = allocator2.RefillCache()
	c.Assert(err, IsNil)
	c.Assert(len(allocator2.cache), Equals, int(maxID))

	// allocate all IDs again using the same set of keys, refcnt should go to 2
	for i := ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		id, new, err := allocator2.Allocate(key)
		c.Assert(err, IsNil)
		c.Assert(id, Not(Equals), 0)
		c.Assert(new, Equals, false)

		// refcnt in the 2nd allocator is 1
		c.Assert(allocator2.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))

		allocator2.Release(key)
	}

	// release 2nd reference of all IDs
	for i := ID(1); i <= maxID; i++ {
		allocator.Release(TestType(fmt.Sprintf("key%04d", i)))
	}

	// refcnt should be back to 1
	for i := ID(1); i <= maxID; i++ {
		key := TestType(fmt.Sprintf("key%04d", i))
		c.Assert(allocator.localKeys.keys[key.GetKey()].refcnt, Equals, uint64(1))
	}

	// running the GC should not evict any entries
	allocator.runGC()

	v, err := Client.ListPrefix(allocator.idPrefix)
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, int(maxID))

	// release final reference of all IDs
	for i := ID(1); i <= maxID; i++ {
		allocator.Release(TestType(fmt.Sprintf("key%04d", i)))
	}

	// running the GC should evict all entries
	allocator.runGC()

	v, err = Client.ListPrefix(allocator.idPrefix)
	c.Assert(err, IsNil)
	c.Assert(len(v), Equals, 0)

	allocator.DeleteAllKeys()
	allocator.Delete()
	allocator2.Delete()
}
