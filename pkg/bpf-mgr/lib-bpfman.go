package bpf_mgr

import (
	"context"
	"encoding/binary"
	"fmt"

	bpfmaniov1alpha1 "github.com/bpfman/bpfman-operator/apis/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	debugLookup                = "debug_lookup" // constant defined in kernel hook to enable lPM lookup
	debugLookupEnvVar          = "ENABLE_EBPF_LPM_LOOKUP_DBG"
	ingressNodeFirewallApp     = "ingress-node-firewall"
	ingressNodeFirewallXDPHook = "xdp_ingress_node_firewall_process"
	ingressNodeFirewallTCXHook = "tcx_ingress_node_firewall_process"
	ingressDirection           = "ingress"
	ingressNodeFirewallBCImage = "quay.io/bpfman-bytecode/ingress-node-firewall:latest"
)

func BpfmanAttachNodeFirewall(ctx context.Context, client client.Client, intf []string, debug bool) error {
	klog.Info("Attaching Node Firewall via eBPF manager")
	return bpfmanCreateNodeFirewallApplication(ctx, client, intf, false, debug)
}

func BpfmanDetachNodeFirewall(ctx context.Context, client client.Client, intf []string, debug bool) error {
	klog.Info("Attaching Node Firewall via eBPF manager")
	return bpfmanCreateNodeFirewallApplication(ctx, client, intf, true, debug)
}

func bpfmanCreateNodeFirewallApplication(ctx context.Context, c client.Client, intf []string, isDelete bool, debug bool) error {
	bpfApp := bpfmaniov1alpha1.BpfApplication{}
	var err error
	var debug_val uint32
	if debug {
		debug_val = 1
	} else {
		debug_val = 0
	}

	debug_buf := make([]byte, 4)
	binary.NativeEndian.PutUint32(debug_buf, debug_val)
	bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{
		debugLookup: debug_buf,
	}

	bpfApp.Name = ingressNodeFirewallApp
	bpfApp.Kind = "BpfApplication"
	bpfApp.Labels = map[string]string{
		"app": ingressNodeFirewallApp,
	}
	bpfApp.Spec.NodeSelector = metav1.LabelSelector{
		MatchLabels: map[string]string{},
	}
	bpfApp.Spec.BpfAppCommon.ByteCode = bpfmaniov1alpha1.BytecodeSelector{
		Image: &bpfmaniov1alpha1.BytecodeImage{
			Url:             ingressNodeFirewallBCImage,
			ImagePullPolicy: bpfmaniov1alpha1.PullAlways,
		},
	}
	bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{}
	bpfApp.Spec.Programs = []bpfmaniov1alpha1.BpfApplicationProgram{
		{
			Type: bpfmaniov1alpha1.ProgTypeXDP,
			XDP: &bpfmaniov1alpha1.XdpProgramInfo{
				BpfProgramCommon: bpfmaniov1alpha1.BpfProgramCommon{
					BpfFunctionName: ingressNodeFirewallXDPHook,
				},
				InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &intf},
			},
		},
		/*
			{
				Type: bpfmaniov1alpha1.ProgTypeTCX,
				TCX: &bpfmaniov1alpha1.TcProgramInfo{
					BpfProgramCommon: bpfmaniov1alpha1.BpfProgramCommon{
						BpfFunctionName: ingressNodeFirewallTCXHook,
					},
					InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &[]string{intf}},
					Direction:         ingressDirection,
				},
			},
		*/
	}
	if !isDelete {
		err = c.Get(ctx, client.ObjectKey{Name: ingressNodeFirewallApp}, &bpfApp)
		if err != nil {
			if errors.IsNotFound(err) {
				klog.Info("Creating BpfApplication Object")

				err = c.Create(ctx, &bpfApp)
				if err != nil {
					return fmt.Errorf("failed to create BpfApplication: %v", err)
				}
			} else {
				return fmt.Errorf("failed to get BpfApplication: %v", err)
			}
		} else {
			klog.Info("Updating BpfApplication Object")
			err = c.Update(ctx, &bpfApp)
			if err != nil {
				return fmt.Errorf("failed to create BpfApplication: %v", err)

			}
		}

	} else {
		err = c.Get(ctx, client.ObjectKey{Name: ingressNodeFirewallApp}, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to get BpfApplication: %v", err)
		}

		klog.Info("Deleting BpfApplication Object")
		err = c.Delete(ctx, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to delete BpfApplication: %v", err)
		}
	}

	return err
}
