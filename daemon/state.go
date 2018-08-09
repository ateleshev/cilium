// Copyright 2016-2018 Authors of Cilium
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
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/workloads"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type endpointRestoreState struct {
	restored []*endpoint.Endpoint
	toClean  []*endpoint.Endpoint
}

// restoreOldEndpoints reads the list of existing endpoints previously managed
// Cilium when it was last run and associated it with container workloads. This
// function performs the first step in restoring the endpoint structure,
// allocating their existing IP out of the CIDR block and then inserting the
// endpoints into the endpoints list. It needs to be followed by a call to
// regenerateRestoredEndpoints() once the endpoint builder is ready.
//
// If clean is true, endpoints which cannot be associated with a container
// workloads are deleted.
func (d *Daemon) restoreOldEndpoints(dir string, clean bool) (*endpointRestoreState, error) {
	state := &endpointRestoreState{
		restored: []*endpoint.Endpoint{},
		toClean:  []*endpoint.Endpoint{},
	}

	if !option.Config.RestoreState {
		log.Info("Endpoint restore is disabled, skipping restore step")
		return state, nil
	}

	log.Info("Restoring endpoints from former life...")

	dirFiles, err := ioutil.ReadDir(dir)
	if err != nil {
		return state, err
	}
	eptsID := endpoint.FilterEPDir(dirFiles)

	possibleEPs := readEPsFromDirNames(dir, eptsID)

	if len(possibleEPs) == 0 {
		log.Info("No old endpoints found.")
		return state, nil
	}

	for _, ep := range possibleEPs {
		scopedLog := log.WithField(logfields.EndpointID, ep.ID)
		skipRestore := false

		// On each restart, the health endpoint is supposed to be recreated.
		// Hence we need to clean health endpoint state unconditionally.
		if ep.HasLabels(labels.LabelHealth) {
			skipRestore = true
		} else {
			if _, err := netlink.LinkByName(ep.IfName); err != nil {
				scopedLog.Infof("Interface %s could not be found for endpoint being restored, ignoring", ep.IfName)
				skipRestore = true
			} else if !workloads.IsRunning(ep) {
				scopedLog.Info("No workload could be associated with endpoint being restored, ignoring")
				skipRestore = true
			}
		}

		if clean && skipRestore {
			state.toClean = append(state.toClean, ep)
			continue
		}

		ep.UnconditionalLock()
		scopedLog.Debug("Restoring endpoint")
		ep.LogStatusOKLocked(endpoint.Other, "Restoring endpoint from previous cilium instance")

		if err := d.allocateIPsLocked(ep); err != nil {
			ep.Unlock()
			scopedLog.WithError(err).Error("Failed to re-allocate IP of endpoint. Not restoring endpoint.")
			state.toClean = append(state.toClean, ep)
			continue
		}

		if option.Config.KeepConfig {
			ep.SetDefaultOpts(nil)
		} else {
			ep.SetDefaultOpts(option.Config.Opts)
			alwaysEnforce := policy.GetPolicyEnabled() == option.AlwaysEnforce
			ep.Options.SetBool(option.IngressPolicy, alwaysEnforce)
			ep.Options.SetBool(option.EgressPolicy, alwaysEnforce)
		}

		ep.Unlock()

		state.restored = append(state.restored, ep)
	}

	log.WithFields(logrus.Fields{
		"count.restored": len(state.restored),
		"count.total":    len(possibleEPs),
	}).Info("Endpoints restored")

	return state, nil
}

func (d *Daemon) regenerateRestoredEndpoints(state *endpointRestoreState) {
	log.Infof("Regenerating %d restored endpoints", len(state.restored))

	// Before regenerating, check whether the CT map has properties that
	// match this Cilium userspace instance. If not, it must be removed
	ctmap.DeleteIfUpgradeNeeded(nil)

	// we need to signalize when the endpoints are regenerated, i.e., when
	// they have finished to rebuild after being restored.
	epRegenerated := make(chan bool, len(state.restored))

	for _, ep := range state.restored {
		// If the endpoint has local conntrack option enabled, then
		// check whether the CT map needs upgrading (and do so).
		if ep.Options.IsEnabled(option.ConntrackLocal) {
			ctmap.DeleteIfUpgradeNeeded(ep)
		}

		// Insert into endpoint manager so it can be regenerated when calls to
		// TriggerPolicyUpdates() are made. This must be done synchronously (i.e.,
		// not in a goroutine) because regenerateRestoredEndpoints must guarantee
		// upon returning that endpoints are exposed to other subsystems via
		// endpointmanager.

		ep.UnconditionalRLock()
		endpointmanager.Insert(ep)
		ep.RUnlock()

		go func(ep *endpoint.Endpoint, epRegenerated chan<- bool) {
			if err := ep.RLockAlive(); err != nil {
				ep.LogDisconnectedMutexAction(err, "before filtering labels during regenerating restored endpoint")
				return
			}
			scopedLog := log.WithField(logfields.EndpointID, ep.ID)
			// Filter the restored labels with the new daemon's filter
			l, _ := labels.FilterLabels(ep.OpLabels.IdentityLabels())
			ep.RUnlock()

			identity, _, err := identityPkg.AllocateIdentity(l)
			if err != nil {
				scopedLog.WithError(err).Warn("Unable to restore endpoint")
				epRegenerated <- false
			}

			if err := ep.LockAlive(); err != nil {
				scopedLog.Warn("Endpoint to restore has been deleted")
				return
			}

			ep.LogStatusOKLocked(endpoint.Other, "Synchronizing endpoint labels with KVStore")

			if ep.SecurityIdentity != nil {
				if oldSecID := ep.SecurityIdentity.ID; identity.ID != oldSecID {
					log.WithFields(logrus.Fields{
						logfields.EndpointID:              ep.ID,
						logfields.IdentityLabels + ".old": oldSecID,
						logfields.IdentityLabels + ".new": identity.ID,
					}).Info("Security identity for endpoint is different from the security identity restored for the endpoint")
				}
			}
			ep.SetIdentity(identity)

			ready := ep.SetStateLocked(endpoint.StateWaitingToRegenerate, "Triggering synchronous endpoint regeneration while syncing state to host")
			ep.Unlock()

			if !ready {
				scopedLog.WithField(logfields.EndpointState, ep.GetState()).Warn("Endpoint in inconsistent state")
				epRegenerated <- false
				return
			}
			if buildSuccess := <-ep.Regenerate(d, "syncing state to host"); !buildSuccess {
				scopedLog.Warn("Failed while regenerating endpoint")
				epRegenerated <- false
				return
			}

			// NOTE: UnconditionalRLock is used here because it's used only for logging an already restored endpoint
			ep.UnconditionalRLock()
			scopedLog.WithField(logfields.IPAddr, []string{ep.IPv4.String(), ep.IPv6.String()}).Info("Restored endpoint")
			ep.RUnlock()
			epRegenerated <- true
		}(ep, epRegenerated)
	}

	for _, ep := range state.toClean {
		go d.deleteEndpointQuiet(ep, true)
	}

	go func() {
		regenerated, total := 0, 0
		if len(state.restored) > 0 {
			for buildSuccess := range epRegenerated {
				if buildSuccess {
					regenerated++
				}
				total++
				if total >= len(state.restored) {
					break
				}
			}
		}
		close(epRegenerated)

		log.WithFields(logrus.Fields{
			"regenerated": regenerated,
			"total":       total,
		}).Info("Finished regenerating restored endpoints")
	}()
}

func (d *Daemon) allocateIPsLocked(ep *endpoint.Endpoint) error {
	err := ipam.AllocateIP(ep.IPv6.IP())
	if err != nil {
		// TODO if allocation failed reallocate a new IP address and setup veth
		// pair accordingly
		return fmt.Errorf("unable to reallocate IPv6 address: %s", err)
	}

	defer func(ep *endpoint.Endpoint) {
		if err != nil {
			ipam.ReleaseIP(ep.IPv6.IP())
		}
	}(ep)

	if !option.Config.IPv4Disabled {
		if ep.IPv4 != nil {
			if err = ipam.AllocateIP(ep.IPv4.IP()); err != nil {
				return fmt.Errorf("unable to reallocate IPv4 address: %s", err)
			}
		}
	}
	return nil
}

// readEPsFromDirNames returns a list of endpoints from a list of directory
// names that can possible contain an endpoint.
func readEPsFromDirNames(basePath string, eptsDirNames []string) []*endpoint.Endpoint {
	possibleEPs := []*endpoint.Endpoint{}
	for _, epID := range eptsDirNames {
		epDir := filepath.Join(basePath, epID)
		readDir := func() string {
			scopedLog := log.WithFields(logrus.Fields{
				logfields.EndpointID: epID,
				logfields.Path:       filepath.Join(epDir, common.CHeaderFileName),
			})
			scopedLog.Debug("Reading directory")
			epFiles, err := ioutil.ReadDir(epDir)
			if err != nil {
				scopedLog.WithError(err).Warn("Error while reading directory. Ignoring it...")
				return ""
			}
			cHeaderFile := common.FindEPConfigCHeader(epDir, epFiles)
			if cHeaderFile == "" {
				return ""
			}
			return cHeaderFile
		}
		// There's an odd issue where the first read dir doesn't work.
		cHeaderFile := readDir()
		if cHeaderFile == "" {
			cHeaderFile = readDir()
		}

		scopedLog := log.WithFields(logrus.Fields{
			logfields.EndpointID: epID,
			logfields.Path:       cHeaderFile,
		})

		if cHeaderFile == "" {
			scopedLog.Info("C header file not found. Ignoring endpoint")
			continue
		}

		scopedLog.Debug("Found endpoint C header file")

		strEp, err := common.GetCiliumVersionString(cHeaderFile)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to read the C header file")
			continue
		}
		ep, err := endpoint.ParseEndpoint(strEp)
		if err != nil {
			scopedLog.WithError(err).Warn("Unable to parse the C header file")
			continue
		}
		possibleEPs = append(possibleEPs, ep)
	}
	return possibleEPs
}

func (d *Daemon) syncLBMapsWithK8s() error {
	k8sServiceIDs := make(map[loadbalancer.ServiceID]struct{})
	k8sDeletedServices := []loadbalancer.LBSVC{}
	// maps service IDs to whether they are IPv4 or IPv6
	k8sDeletedRevNATS := make(map[loadbalancer.ServiceID]bool)

	// Make sure we can't update the K8s service lock
	// or the BPF maps while we are iterating over each
	// to avoid having one updated before the other
	// in parallel, resulting in inadvertent deletions
	// of services from the BPF maps
	d.loadBalancer.K8sMU.Lock()
	log.Debugf("acquire K8sMU controller")
	defer d.loadBalancer.K8sMU.Unlock()

	d.loadBalancer.BPFMapMU.Lock()
	log.Debugf("acquire BPFMapMU controller")
	defer d.loadBalancer.BPFMapMU.Unlock()

	log.Debugf("syncing BPF loadbalancer map with in-memory Kubernetes service map")

	// Get all Cilium Service IDs from Kubernetes Services;
	// these IDs are the keys for the BPF map which we need
	// to make comparisons against to see if we need
	// to delete entries from the BPF maps.
	for _, k8sServiceInfo := range d.loadBalancer.K8sServices {
		for _, frontendPort := range k8sServiceInfo.Ports {
			k8sServiceIDs[frontendPort.ID] = struct{}{}
			log.WithField(logfields.ServiceID, frontendPort.ID).Debug("adding service to set of services to check against loadbalancer map BPF contents")
		}
	}

	log.Debugf("dumping BPF loadbalancer maps to userspace")
	_, newSVCList, lbmapDumpErrors := dumpBPFServiceMapsToUserspace()
	if len(lbmapDumpErrors) > 0 {
		errorStrings := ""
		for _, err := range lbmapDumpErrors {
			errorStrings = fmt.Sprintf("%s, %s", err, errorStrings)
		}
		return fmt.Errorf("error(s): %s", errorStrings)
	}

	newRevNATMap, revNATMapDumpErrors := dumpBPFRevNatMapsToUserspace()
	if len(revNATMapDumpErrors) > 0 {
		errorStrings := ""
		for _, err := range revNATMapDumpErrors {
			errorStrings = fmt.Sprintf("%s, %s", err, errorStrings)
		}
		return fmt.Errorf("error(s): %s", errorStrings)
	}

	for _, svc := range newSVCList {

		// If Kubernetes is enabled, the the list of services managed by it are
		// the only services that Cilium will allow to be plumbed into the
		// datapath. Any other loadbalancer map entry which does not exist in
		// the set of services Cilium manages for Kubernetes will be removed
		// from the loadbalancer maps. This handles the case where Cilium
		// is not running, and a service is deleted from Kubernetes which is
		// managed by Cilium. Because Cilium is not running, the BPF map entry
		// for said service will not be deleted when the delete call is made
		// to Kubernetes. Once Cilium starts up again,
		// it needs to account for this case and clean up any services it
		// didn't have a chance to clean up because it was not running.
		if _, ok := k8sServiceIDs[svc.FE.ID]; !ok {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: svc.FE.ID,
				logfields.L3n4Addr:  logfields.Repr(svc.FE.L3n4Addr)}).Debug("service ID read from BPF maps is not managed by K8s; will delete it from BPF maps")
			k8sDeletedServices = append(k8sDeletedServices, *svc)
		}
	}

	for serviceID, serviceInfo := range newRevNATMap {
		if _, ok := d.loadBalancer.RevNATMap[serviceID]; !ok {
			log.WithFields(logrus.Fields{
				logfields.ServiceID: serviceID,
				logfields.L3n4Addr:  logfields.Repr(serviceInfo)}).Debug("revNAT ID read from BPF maps is not managed by K8s; will delete it from BPF maps")
			// If IPv6
			if serviceInfo.IP.To4() == nil {
				k8sDeletedRevNATS[serviceID] = false
			} else {
				k8sDeletedRevNATS[serviceID] = true
			}
		}
	}

	bpfDeleteErrors := make([]error, 0, len(k8sDeletedServices))

	for _, svc := range k8sDeletedServices {
		svcLogger := log.WithField(logfields.Object, logfields.Repr(svc.FE))
		svcLogger.Debug("removing service because it was not synced from Kubernetes")
		if err := d.svcDeleteBPF(&svc); err != nil {
			bpfDeleteErrors = append(bpfDeleteErrors, err)
		}
	}

	for serviceID, isIPv4 := range k8sDeletedRevNATS {
		log.WithFields(logrus.Fields{logfields.ServiceID: serviceID, "isIPv4": isIPv4}).Debug("removing revNAT because it was not synced from Kubernetes")
		if err := d.deleteRevNATBPFLocked(serviceID, isIPv4); err != nil {
			bpfDeleteErrors = append(bpfDeleteErrors, err)
		}
	}

	if len(bpfDeleteErrors) > 0 {
		bpfErrorsString := ""
		for _, err := range bpfDeleteErrors {
			bpfErrorsString = fmt.Sprintf("%s, %s", err, bpfErrorsString)
		}
		return fmt.Errorf("Errors deleting BPF map entries: %s", bpfErrorsString)
	}

	log.Debugf("successfully synced BPF loadbalancer and revNAT maps with in-memory Kubernetes service maps")

	return nil
}
