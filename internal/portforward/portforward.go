// Package portforward runs an in-process kubectl-style port-forward on top of
// client-go's SPDY dialer. Unlike client-go's built-in port-forward wrapper
// (which always binds a TCP listener on 127.0.0.1), this implementation
// accepts connections on a caller-supplied net.Listener — letting kubeport
// bind the tunnel to an authenticated IPC endpoint (Unix domain socket or
// Windows named pipe) so other local processes cannot bypass the HTTPS
// terminator by dialing the upstream TCP port.
package portforward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport/spdy"
)

// Forwarder tunnels bytes accepted on Listener to targetPort on pod Namespace/PodName.
type Forwarder struct {
	Namespace  string
	PodName    string
	TargetPort int

	Listener net.Listener

	clientset *kubernetes.Clientset
	config    *rest.Config
	stderr    io.Writer

	requestID int32

	mu         sync.Mutex
	streamConn httpstream.Connection
	started    bool
	closed     bool

	readyCh chan struct{}
	errCh   chan error
	stopCh  chan struct{}
}

// New builds a Forwarder. The caller supplies an already-bound net.Listener;
// Start() takes ownership and closes it on Stop().
func New(cfg *rest.Config, cs *kubernetes.Clientset, namespace, pod string, listener net.Listener, targetPort int, _, stderr io.Writer) *Forwarder {
	return &Forwarder{
		Namespace:  namespace,
		PodName:    pod,
		TargetPort: targetPort,
		Listener:   listener,
		config:     cfg,
		clientset:  cs,
		stderr:     stderr,
		readyCh:    make(chan struct{}),
		errCh:      make(chan error, 1),
		stopCh:     make(chan struct{}),
	}
}

// Start opens the SPDY connection to the apiserver and begins accepting on
// Listener in a background goroutine. Returns once the connection is
// established (or fails); per-accept stream creation happens lazily.
func (f *Forwarder) Start(ctx context.Context) error {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return errors.New("forwarder already started")
	}
	f.started = true
	f.mu.Unlock()

	rt, upgrader, err := spdy.RoundTripperFor(f.config)
	if err != nil {
		return fmt.Errorf("build spdy round tripper: %w", err)
	}

	url := f.clientset.CoreV1().RESTClient().
		Post().
		Resource("pods").
		Namespace(f.Namespace).
		Name(f.PodName).
		SubResource("portforward").
		URL()

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: rt}, "POST", url)

	streamConn, _, err := dialer.Dial("portforward.k8s.io")
	if err != nil {
		return fmt.Errorf("dial portforward: %w", err)
	}

	f.mu.Lock()
	f.streamConn = streamConn
	f.mu.Unlock()

	close(f.readyCh)

	go f.acceptLoop()
	go f.watchStreamConn()

	return nil
}

func (f *Forwarder) acceptLoop() {
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case f.errCh <- fmt.Errorf("accept: %w", err):
			default:
			}
			return
		}
		go f.handleConn(c)
	}
}

func (f *Forwarder) watchStreamConn() {
	f.mu.Lock()
	sc := f.streamConn
	f.mu.Unlock()
	if sc == nil {
		return
	}
	<-sc.CloseChan()
	select {
	case f.errCh <- errors.New("port-forward connection closed by apiserver"):
	default:
	}
}

// handleConn services a single accepted connection: create a data + error
// stream pair on the multiplexed SPDY connection, then pipe bytes in both
// directions until either side closes.
func (f *Forwarder) handleConn(c net.Conn) {
	defer c.Close()

	f.mu.Lock()
	sc := f.streamConn
	closed := f.closed
	f.mu.Unlock()
	if sc == nil || closed {
		return
	}

	requestID := atomic.AddInt32(&f.requestID, 1)

	errorHeaders := http.Header{}
	errorHeaders.Set(corev1.StreamType, corev1.StreamTypeError)
	errorHeaders.Set(corev1.PortHeader, strconv.Itoa(f.TargetPort))
	errorHeaders.Set(corev1.PortForwardRequestIDHeader, strconv.Itoa(int(requestID)))
	errorStream, err := sc.CreateStream(errorHeaders)
	if err != nil {
		fmt.Fprintf(f.stderr, "kubeport: create error stream: %v\n", err)
		return
	}
	// Client side does not write to the error stream; close our write half.
	_ = errorStream.Close()

	go func() {
		msg, err := io.ReadAll(errorStream)
		if err != nil && !errors.Is(err, io.EOF) {
			return
		}
		if len(msg) > 0 {
			text := string(msg)
			if strings.HasSuffix(text, "\n") {
				fmt.Fprintf(f.stderr, "kubeport: upstream error: %s", text)
			} else {
				fmt.Fprintf(f.stderr, "kubeport: upstream error: %s\n", text)
			}
		}
	}()

	dataHeaders := http.Header{}
	dataHeaders.Set(corev1.StreamType, corev1.StreamTypeData)
	dataHeaders.Set(corev1.PortHeader, strconv.Itoa(f.TargetPort))
	dataHeaders.Set(corev1.PortForwardRequestIDHeader, strconv.Itoa(int(requestID)))
	dataStream, err := sc.CreateStream(dataHeaders)
	if err != nil {
		fmt.Fprintf(f.stderr, "kubeport: create data stream: %v\n", err)
		return
	}
	defer dataStream.Reset()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(dataStream, c)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, dataStream)
		done <- struct{}{}
	}()
	<-done
}

// Stop tears down the accept loop and SPDY connection. Safe to call multiple times.
func (f *Forwarder) Stop() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	sc := f.streamConn
	f.mu.Unlock()

	if f.Listener != nil {
		_ = f.Listener.Close()
	}
	if sc != nil {
		_ = sc.Close()
	}
	close(f.stopCh)
}

// Err returns a channel that produces any background error from the tunnel.
func (f *Forwarder) Err() <-chan error { return f.errCh }

// Ready returns a channel closed once the SPDY connection is established.
func (f *Forwarder) Ready() <-chan struct{} { return f.readyCh }
