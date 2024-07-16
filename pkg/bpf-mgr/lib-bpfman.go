package bpf_mgr

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	bpfmaniov1alpha1 "github.com/bpfman/bpfman-operator/apis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	debugLookup                = "debug_lookup" // constant defined in kernel hook to enable lPM lookup
	debugLookupEnvVar          = "ENABLE_EBPF_LPM_LOOKUP_DBG"
	ingressNodeFirewallApp     = "ingress-node-firewall"
	ingressNodeFirewallXDPHook = "xdp_ingress_node_firewall_process"
	ingressNodeFirewallTCXHook = "tcx_ingress_node_firewall_process"
	ingressDirection           = "ingress"
	ingressNodeFirewallBCImage = "quay.io/bpfman-bytecode/ingress-node-firewall"
)

func BpfmanAttachNodeFirewall(ctx context.Context, client client.Client, intf string) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, intf, false)
}

func BpfmanDetachNodeFirewall(ctx context.Context, client client.Client, intf string) error {
	return bpfmanCreateNodeFirewallApplication(ctx, client, intf, true)
}

func bpfmanCreateNodeFirewallApplication(ctx context.Context, c client.Client, intf string, isDelete bool) error {
	bpfApp := bpfmaniov1alpha1.BpfApplication{}
	var err error
	debugLookupVal, ok := os.LookupEnv(debugLookupEnvVar)
	if ok {
		val, err := strconv.Atoi(debugLookupVal)
		if err != nil {
			return fmt.Errorf("failed to convert %q to integer: %v", debugLookupVal, err)
		}
		debug := make([]byte, 4)
		binary.NativeEndian.PutUint32(debug, uint32(val))
		bpfApp.Spec.BpfAppCommon.GlobalData = map[string][]byte{
			debugLookup: debug,
		}
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
			ImagePullPolicy: bpfmaniov1alpha1.PullIfNotPresent,
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
				InterfaceSelector: bpfmaniov1alpha1.InterfaceSelector{Interfaces: &[]string{intf}},
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
		err = c.Create(ctx, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to create BpfApplication: %v", err)
		}
	} else {
		err = c.Get(ctx, client.ObjectKey{Name: ingressNodeFirewallApp}, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to get BpfApplication: %v", err)
		}
		err = c.Delete(ctx, &bpfApp)
		if err != nil {
			return fmt.Errorf("failed to delete BpfApplication: %v", err)
		}
	}

	return err
}
