// Package kube centralises kubeconfig loading, context/namespace discovery
// and target resolution (pod/service → pod + target port).
package kube

import (
	"context"
	"errors"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client is a resolved Kubernetes client plus context metadata.
type Client struct {
	Config      *rest.Config
	Clientset   *kubernetes.Clientset
	ContextName string
	Namespace   string
}

// LoadClient builds a Kubernetes client from the default kubeconfig chain,
// optionally overriding the context and/or kubeconfig path. If namespace is
// empty, the namespace configured in the selected context is used.
func LoadClient(kubeconfigPath, contextName, namespace string) (*Client, error) {
	var rules *clientcmd.ClientConfigLoadingRules
	if kubeconfigPath != "" {
		if _, err := os.Stat(kubeconfigPath); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("kubeconfig not found at %s (hint: run `az aks get-credentials` as the target user, or pass --kubeconfig with an explicit path)", kubeconfigPath)
			}
			return nil, fmt.Errorf("kubeconfig %s: %w", kubeconfigPath, err)
		}
		// When the caller specifies an explicit path, build a minimal rules
		// object with no Precedence chain and no MigrationRules. This avoids
		// a nasty interaction on Windows split admin accounts: client-go's
		// default MigrationRules try to copy $HOME/.kube/config into
		// %USERPROFILE%/.kube/config, but %USERPROFILE% is frozen at
		// package-init time (= the elevated admin user) while $HOME is
		// what we set at runtime via --user (= the invoking user). The
		// "migration" then fails to open the elevated user's non-existent
		// .kube dir and bubbles up a misleading "path not found" error.
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	} else {
		rules = clientcmd.NewDefaultClientConfigLoadingRules()
		// Same rationale as above: disable the legacy migration even for
		// the default chain — kubeport never wants files auto-copied
		// between user profiles.
		rules.MigrationRules = nil
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	restCfg, err := clientConfig.ClientConfig()
	if err != nil {
		effective := kubeconfigPath
		if effective == "" {
			effective = rules.GetDefaultFilename()
		}
		return nil, fmt.Errorf("build client config (kubeconfig=%s): %w", effective, err)
	}

	rawCfg, err := clientConfig.RawConfig()
	if err != nil {
		return nil, fmt.Errorf("load raw kubeconfig: %w", err)
	}
	ctxName := contextName
	if ctxName == "" {
		ctxName = rawCfg.CurrentContext
	}

	if namespace == "" {
		ns, _, err := clientConfig.Namespace()
		if err != nil {
			return nil, fmt.Errorf("resolve namespace: %w", err)
		}
		namespace = ns
	}
	if namespace == "" {
		namespace = "default"
	}

	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}

	return &Client{
		Config:      restCfg,
		Clientset:   cs,
		ContextName: ctxName,
		Namespace:   namespace,
	}, nil
}

// Target identifies a single pod + port to forward to.
type Target struct {
	PodName    string
	Namespace  string
	TargetPort int
}

// ResolvePod finds a running, ready pod for the given selector. The
// caller must supply an explicit target port (container port on the pod).
func (c *Client) ResolvePod(ctx context.Context, podName string, targetPort int) (*Target, error) {
	if podName == "" {
		return nil, errors.New("pod name is required")
	}
	if targetPort <= 0 {
		return nil, errors.New("target port is required for pod targets")
	}
	pod, err := c.Clientset.CoreV1().Pods(c.Namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", c.Namespace, podName, err)
	}
	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod %s/%s is not Running (phase=%s)", c.Namespace, podName, pod.Status.Phase)
	}
	return &Target{
		PodName:    pod.Name,
		Namespace:  pod.Namespace,
		TargetPort: targetPort,
	}, nil
}

// ResolveService looks up a service by name, picks a ready pod from its
// selector, and resolves the target port (optionally overridden by
// portOverride, which matches against service port name or number).
func (c *Client) ResolveService(ctx context.Context, serviceName string, portOverride string) (*Target, error) {
	svc, err := c.Clientset.CoreV1().Services(c.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get service %s/%s: %w", c.Namespace, serviceName, err)
	}
	if len(svc.Spec.Selector) == 0 {
		return nil, fmt.Errorf("service %s/%s has no selector (headless or externalName services not supported)", c.Namespace, serviceName)
	}

	port, err := pickServicePort(svc, portOverride)
	if err != nil {
		return nil, err
	}

	selector := labels.SelectorFromSet(svc.Spec.Selector)
	pods, err := c.Clientset.CoreV1().Pods(c.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods for service %s: %w", serviceName, err)
	}

	pod := pickReadyPod(pods.Items)
	if pod == nil {
		return nil, fmt.Errorf("no ready pods matching service %s selector %s", serviceName, selector.String())
	}

	targetPort, err := resolveTargetPort(pod, port)
	if err != nil {
		return nil, err
	}

	return &Target{
		PodName:    pod.Name,
		Namespace:  pod.Namespace,
		TargetPort: targetPort,
	}, nil
}

func pickServicePort(svc *corev1.Service, override string) (corev1.ServicePort, error) {
	if len(svc.Spec.Ports) == 0 {
		return corev1.ServicePort{}, fmt.Errorf("service %s has no ports", svc.Name)
	}
	if override == "" {
		return svc.Spec.Ports[0], nil
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == override {
			return p, nil
		}
		if fmt.Sprintf("%d", p.Port) == override {
			return p, nil
		}
	}
	return corev1.ServicePort{}, fmt.Errorf("service %s has no port matching %q", svc.Name, override)
}

func pickReadyPod(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		p := &pods[i]
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return p
			}
		}
	}
	// Fall back to any Running pod if none report Ready (e.g. probes disabled).
	for i := range pods {
		if pods[i].Status.Phase == corev1.PodRunning {
			return &pods[i]
		}
	}
	return nil
}

func resolveTargetPort(pod *corev1.Pod, svcPort corev1.ServicePort) (int, error) {
	switch svcPort.TargetPort.Type {
	case intstr.Int:
		return int(svcPort.TargetPort.IntVal), nil
	case intstr.String:
		name := svcPort.TargetPort.StrVal
		for _, c := range pod.Spec.Containers {
			for _, p := range c.Ports {
				if p.Name == name {
					return int(p.ContainerPort), nil
				}
			}
		}
		return 0, fmt.Errorf("pod %s has no container port named %q", pod.Name, name)
	default:
		return int(svcPort.Port), nil
	}
}
