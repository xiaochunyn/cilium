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
	. "gopkg.in/check.v1"
)

func (s *AllocatorSuite) TestLocalKeys(c *C) {
	k := newLocalKeys()
	key, val := "foo", int(200)
	key2, val2 := "bar", int(200)

	v := k.get(key)
	c.Assert(v, IsNil)

	v = k.allocate(key, val) // refcnt=1
	vInt, ok := v.(int)
	c.Assert(ok, Equals, true)
	c.Assert(vInt, Equals, val)

	v = k.get(key) // refcnt=2
	vInt, ok = v.(int)
	c.Assert(ok, Equals, true)
	c.Assert(vInt, Equals, val)
	k.release(key) // refcnt=1

	v = k.allocate(key, val) // refcnt=2
	vInt, ok = v.(int)
	c.Assert(ok, Equals, true)
	c.Assert(vInt, Equals, val)

	v = k.allocate(key2, val2) // refcnt=1
	vInt, ok = v.(int)
	c.Assert(ok, Equals, true)
	c.Assert(vInt, Equals, val2)

	k.release(key) // refcnt=1
	v = k.get(key) // refcnt=2
	vInt, ok = v.(int)
	c.Assert(ok, Equals, true)
	c.Assert(vInt, Equals, val)

	k.release(key) // refcnt=1
	k.release(key) // refcnt=0
	v = k.get(key)
	c.Assert(v, IsNil)

	k.release(key2) // refcnt=0
	v = k.get(key2)
	c.Assert(v, IsNil)
}
