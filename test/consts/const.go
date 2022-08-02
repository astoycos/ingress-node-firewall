package consts

const (
	// IngressNodeFirewallOperatorDeploymentName contains the name of the IngressNodeFirewall Operator deployment
	IngressNodeFirewallOperatorDeploymentName = "ingress-node-firewall-controller-manager"
	// IngressNodeFirewallOperatorDeploymentLabel contains the label of the IngressNodeFirewall Operator deployment
	IngressNodeFirewallOperatorDeploymentLabel = "controller-manager"
	// IngressNodeFirewallConfigCRDName contains the name of the IngressNodeFirewall Config CRD
	IngressNodeFirewallConfigCRDName = "ingressnodefirewallconfigs.ingress-nodefw.ingress-nodefw"
	// IngressNodeFirewallRulesCRDName contains the name of the IngressNodeFirewall Rules CRD
	IngressNodeFirewallRulesCRDName = "ingressnodefirewalls.ingress-nodefw.ingress-nodefw"
	// IngressNodeFirewallNodeStateCRDName contains the name of the IngressNodeFirewall NodeState CRD
	IngressNodeFirewallNodeStateCRDName = "ingressnodefirewallnodestates.ingress-nodefw.ingress-nodefw"
	// IngressNodeFirewallDaemonsetName contains the name of the IngressNodeFirewall daemonset
	IngressNodeFirewallDaemonsetName = "ingress-node-firewall-daemon"
	// DefaultOperatorNameSpace is the default operator namespace
	DefaultOperatorNameSpace = "ingress-node-firewall-system"
	// IngressNodeFirewallConfigCRFile configuration yaml file
	IngressNodeFirewallConfigCRFile = "ingress-node-firewall-config.yaml"
)