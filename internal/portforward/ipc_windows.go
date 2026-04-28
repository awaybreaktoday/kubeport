//go:build windows

package portforward

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func listenIPC(name string) (net.Listener, error) {
	sid, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("current user sid: %w", err)
	}
	// O:<sid>   owner
	// G:<sid>   primary group
	// D:(A;;GA;;;<sid>)  DACL: allow (A) GENERIC_ALL (GA) to <sid>
	sddl := fmt.Sprintf("O:%sG:%sD:(A;;GA;;;%s)", sid, sid, sid)
	cfg := &winio.PipeConfig{
		SecurityDescriptor: sddl,
	}
	ln, err := winio.ListenPipe(name, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", name, err)
	}
	return wrapPeerVerify(ln), nil
}

func dialIPC(ctx context.Context, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, name)
}

func defaultIPCEndpoint() (string, error) {
	return `\\.\pipe\kubeport-` + strconv.Itoa(os.Getpid()), nil
}

func currentUserSID() (string, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}
