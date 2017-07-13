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

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"

	log "github.com/Sirupsen/logrus"
)

// EndpointLabels are the labels of an endpoint
type EndpointLabels struct {
	// Active labels that are enabled and disabled but not deleted
	Custom labels.Labels

	// Labels derived from orchestration system
	Orchestration labels.Labels

	// Orchestration labels which have been disabled
	Disabled labels.Labels
}

// NewEndpointLabels returns an empty EndpointLabels struct
func NewEndpointLabels() EndpointLabels {
	return EndpointLabels{
		Custom:        labels.Labels{},
		Disabled:      labels.Labels{},
		Orchestration: labels.Labels{},
	}
}

// DeepCopy returns deep copy of the label.
func (el *EndpointLabels) DeepCopy() *EndpointLabels {
	return &EndpointLabels{
		Custom:        el.Custom.DeepCopy(),
		Disabled:      el.Disabled.DeepCopy(),
		Orchestration: el.Orchestration.DeepCopy(),
	}
}

// Enabled returns map of enabled labels.
func (el *EndpointLabels) Enabled() labels.Labels {
	enabled := make(labels.Labels, len(el.Custom)+len(el.Orchestration))

	for k, v := range el.Custom {
		enabled[k] = v
	}

	for k, v := range el.Orchestration {
		enabled[k] = v
	}

	return enabled
}

// NewEndpointLabelsFromModel creates new EndpointLabels from the API model
func NewEndpointLabelsFromModel(base *models.LabelConfiguration) *EndpointLabels {
	if base == nil {
		return nil
	}

	return &EndpointLabels{
		Custom:        labels.NewLabelsFromModel(base.Custom),
		Disabled:      labels.NewLabelsFromModel(base.Disabled),
		Orchestration: labels.NewLabelsFromModel(base.OrchestrationSystem),
	}
}

// UpdateOrchestrationLabels updates the labels of an endpoint that are derived
// from the orchestration system
func (e *Endpoint) UpdateOrchestrationLabels(owner Owner, l labels.Labels) (bool, error) {
	changed := false

	oldLabels := e.Labels.DeepCopy()
	newLabels := oldLabels.DeepCopy()

	newLabels.Orchestration.MarkAllForDeletion()
	newLabels.Disabled.MarkAllForDeletion()

	for k, v := range l {
		if newLabels.Disabled[k] != nil {
			newLabels.Disabled[k].DeletionMark = false
		} else {
			if newLabels.Orchestration[k] != nil {
				newLabels.Orchestration[k].DeletionMark = false
			} else {
				newLabels.Orchestration[k] = v.DeepCopy()
				changed = true
			}
		}
	}

	if newLabels.Orchestration.DeleteMarked() || newLabels.Disabled.DeleteMarked() {
		changed = true
	}

	log.Debugf("Updating orchestration labels for endpoint %s from %v to %v",
		e.StringID(), oldLabels, newLabels)

	return changed, e.replaceIdentity(owner, newLabels, oldLabels)
}

// LabelsChangeRequest is a request for label changes
type LabelsChangeRequest struct {
	Add    labels.Labels
	Delete labels.Labels
}

// IsEmpty returns true if the label request is empty
func (l *LabelsChangeRequest) IsEmpty() bool {
	return len(l.Add) == 0 && len(l.Delete) == 0
}

func (e *Endpoint) replaceIdentity(owner Owner, newLabels, oldLabels *EndpointLabels) error {
	// No change in labels
	if oldLabels.Enabled().String() == newLabels.Enabled().String() {
		return nil
	}

	id, _, err := identity.Allocate(newLabels.Enabled(), e.StringID())
	if err != nil {
		return err
	}

	log.Debugf("Allocated identity %s for endpoint %s", id, e.StringID())

	// The endpoint was unlocked and could have been removed while we
	// resolved the identity, make sure it still exists
	owner.RLockEndpoints()
	ep := owner.LookupLocked(e.ID)
	if ep == nil {
		owner.RUnlockEndpoints()
		identity.Release(newLabels.Enabled(), e.StringID())
		log.Debugf("Endpoint disappeared while updating labels")
		return fmt.Errorf("endpoint disappeared updating identity")
	}

	ep.Mutex.Lock()
	ep.Labels = *newLabels
	ep.setIdentityLocked(owner, id)
	ep.Mutex.Unlock()
	owner.RUnlockEndpoints()

	// release the old identity
	identity.Release(oldLabels.Enabled(), ep.StringID())

	ep.Regenerate(owner)

	return nil
}

// ApplyLabelChanges applies the requested label changes to the endpoint and
// updates the endpoint's identity
func (e *Endpoint) ApplyLabelChanges(owner Owner, req LabelsChangeRequest) error {
	e.Mutex.Lock()
	oldLabels := e.Labels.DeepCopy()
	e.Mutex.Unlock()

	newLabels := oldLabels.DeepCopy()

	if len(req.Delete) > 0 {
		for k := range req.Delete {
			// The change request is accepted if the label is on
			// any of the lists. If the label is already disabled,
			// we will simply ignore that change.
			if newLabels.Orchestration[k] != nil ||
				newLabels.Custom[k] != nil ||
				newLabels.Disabled[k] != nil {
				break
			}

			return fmt.Errorf("label %s not found", k)
		}
	}

	if len(req.Delete) > 0 {
		for k, v := range req.Delete {
			if newLabels.Orchestration[k] != nil {
				delete(newLabels.Orchestration, k)
				newLabels.Disabled[k] = v
			}

			if newLabels.Custom[k] != nil {
				delete(newLabels.Custom, k)
			}
		}
	}

	if len(req.Add) > 0 {
		for k, v := range req.Add {
			if newLabels.Disabled[k] != nil {
				delete(newLabels.Disabled, k)
				newLabels.Orchestration[k] = v
			} else if newLabels.Orchestration[k] == nil {
				newLabels.Custom[k] = v
			}
		}
	}

	return e.replaceIdentity(owner, newLabels, oldLabels)
}
