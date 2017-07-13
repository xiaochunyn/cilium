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
	"github.com/cilium/cilium/api/v1/models"
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
func (e *Endpoint) UpdateOrchestrationLabels(l labels.Labels) bool {
	changed := false

	e.Labels.Orchestration.MarkAllForDeletion()
	e.Labels.Disabled.MarkAllForDeletion()

	for k, v := range l {
		if e.Labels.Disabled[k] != nil {
			e.Labels.Disabled[k].DeletionMark = false
		} else {
			if e.Labels.Orchestration[k] != nil {
				e.Labels.Orchestration[k].DeletionMark = false
			} else {
				tmp := v.DeepCopy()
				log.Debugf("Assigning orchestration label %+v", tmp)
				e.Labels.Orchestration[k] = tmp
				changed = true
			}
		}
	}

	if e.Labels.Orchestration.DeleteMarked() || e.Labels.Disabled.DeleteMarked() {
		changed = true
	}

	return changed
}
