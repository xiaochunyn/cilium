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
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/events"
	"github.com/cilium/cilium/pkg/identity"

	log "github.com/Sirupsen/logrus"
	dockerAPI "github.com/docker/engine-api/client"
	ctx "golang.org/x/net/context"
)

// RestoreState syncs cilium state against the containers running in the host. dir is the
// cilium's running directory. If clean is set, the endpoints that don't have its
// container in running state are deleted.
func (d *Daemon) RestoreState(dir string, clean bool) error {
	restored := 0

	log.Info("Recovering old running endpoints...")

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Debug("No old endpoints found.")
		return nil
	}

	for _, ep := range possibleEPs {
		log.Debugf("Restoring endpoint ID %d", ep.ID)

		if err := d.resolveIdentity(ep); err != nil {
			log.Warningf("Unable to restore endpoint %s: %s", ep.StringID(), err)
			continue
		}

		if d.conf.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			ep.SetDefaultOpts(d.conf.Opts)
		}

		if buildSuccess := <-ep.Regenerate(d); !buildSuccess {
			log.Warningf("Failed to build endpoint %s while restoring", ep.StringID())
		}

		endpointmanager.Insert(ep)
		restored++

		log.Infof("Restored endpoint: %d", ep.ID)
	}

	log.Infof("Restored %d endpoints", restored)

	if clean {
		d.cleanUpDockerDandlingEndpoints()
	}

	endpointmanager.Mutex.Lock()
	for k := range endpointmanager.Endpoints {
		ep := endpointmanager.Endpoints[k]
		if err := d.allocateIPs(ep); err != nil {
			log.Errorf("Failed while reallocating ep %d's IP addresses: %s. Endpoint won't be restored", ep.ID, err)
			d.deleteEndpoint(ep)
			continue
		}

		log.Infof("EP %d's IP addresses successfully reallocated", ep.ID)
		if buildSuccess := <-ep.Regenerate(d); !buildSuccess {
			log.Warningf("Failed while regenerating endpoint %d: %s", ep.ID, err)
			continue
		}
		ep.Mutex.RLock()
		epID := ep.ID
		if ep.SecLabel != nil {
			epLabels := ep.SecLabel.DeepCopy()
			ep.Mutex.RUnlock()
			d.events <- *events.NewEvent(events.IdentityAdd, epLabels)
		} else {
			ep.Mutex.RUnlock()
		}
		log.Infof("Restored endpoint %d", epID)
	}
	endpointmanager.Mutex.Unlock()

	return nil
}

func (d *Daemon) allocateIPs(ep *endpoint.Endpoint) error {
	ep.Mutex.RLock()
	defer ep.Mutex.RUnlock()
	err := d.AllocateIP(ep.IPv6.IP())
	if err != nil {
		// TODO if allocation failed reallocate a new IP address and setup veth
		// pair accordingly
		return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
	}

	defer func(ep *endpoint.Endpoint) {
		if err != nil {
			d.ReleaseIP(ep.IPv6.IP())
		}
	}(ep)

	if !d.conf.IPv4Disabled {
		if ep.IPv4 != nil {
			if err = d.AllocateIP(ep.IPv4.IP()); err != nil {
				return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
			}
		}
	}
	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory names that
// possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*endpoint.Endpoint {
	possibleEPs := []*endpoint.Endpoint{}
	for _, epID := range eptsDirNames {
		epDir := filepath.Join(basePath, epID)
		readDir := func() string {
			log.Debugf("Reading directory %s\n", epDir)
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				log.Warningf("Error while reading directory %q. Ignoring it...", epDir)
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				log.Infof("File %q not found in %q. Ignoring endpoint %s.",
					common.CHeaderFileName, epDir, epID)
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}
		log.Debugf("Found endpoint C header file %q\n", cHeaderFile)
		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		ep, err := endpoint.ParseEndpoint(strEp)
		if err != nil {
			log.Warningf("Unable to read the C header file %q: %s\n", cHeaderFile, err)
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

// resolveIdentity fetches and restores the identity of the endpoint being restored.
func (d *Daemon) resolveIdentity(ep *endpoint.Endpoint) error {
	if ep.SecLabel == nil {
		// No labels attached, skip identity allocation
		return nil
	}

	// Although the endpoint may have an identity associated with it
	// already. It needs to be resolved properly for the following reasons:
	//  - the reference count on the identity needs to account for this
	//    endpoint
	//  - the labels -> identity mapping may have changed while the agent
	//    was down. The endpoint may need to be assigned a new identity.
	id, _, err := identity.Allocate(ep.SecLabel.Labels, ep.StringID())
	if err != nil {
		return fmt.Errorf("unable to allocate identity: %s", err)
	}

	if id.ID != ep.SecLabel.ID {
		log.Debugf("restore: Endpoint %d has switch identity %d->%d",
			ep.ID, ep.SecLabel.ID, id.ID)
	}

	ep.SetIdentity(d, id)

	return nil
}

// cleanUpDockerDandlingEndpoints cleans all endpoints that are dandling by checking out
// if a particular endpoint has its container running.
func (d *Daemon) cleanUpDockerDandlingEndpoints() {
	cleanUp := func(ep *endpoint.Endpoint) {
		log.Infof("Endpoint %d not found in docker, cleaning up...", ep.ID)
		ep.Mutex.RUnlock()
		d.deleteEndpoint(ep)
	}

	for k := range endpointmanager.Endpoints {
		ep := endpointmanager.Endpoints[k]
		ep.Mutex.RLock()
		log.Debugf("Checking if endpoint is running in docker %d", ep.ID)
		if ep.DockerNetworkID != "" {
			nls, err := d.dockerClient.NetworkInspect(ctx.Background(), ep.DockerNetworkID)
			if dockerAPI.IsErrNetworkNotFound(err) {
				cleanUp(ep)
				continue
			}
			if err != nil {
				ep.Mutex.RUnlock()
				continue
			}
			found := false
			for _, v := range nls.Containers {
				if v.EndpointID == ep.DockerEndpointID {
					found = true
					break
				}
			}
			if !found {
				cleanUp(ep)
				continue
			}
		} else if ep.DockerID != "" {
			cont, err := d.dockerClient.ContainerInspect(ctx.Background(), ep.DockerID)
			if dockerAPI.IsErrContainerNotFound(err) {
				cleanUp(ep)
				continue
			}
			if err != nil {
				ep.Mutex.RUnlock()
				continue
			}
			if !cont.State.Running {
				cleanUp(ep)
				continue
			}
		} else {
			cleanUp(ep)
			continue
		}
	}
}
