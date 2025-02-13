package tunnel

//import (
//	"context"
//	"crypto/tls"
//	"fmt"
//	"github.com/projectcalico/calico/guardian/pkg/chanutil"
//	log "github.com/sirupsen/logrus"
//	"net"
//)
//
//// ErrManagerClosed is returned when a closed manager is used
//var ErrManagerClosed = fmt.Errorf("manager closed")
//
//// ErrTunnelSet is returned when the tunnel has already been set and you try to set it again with one of the SetTunnel.
//var ErrTunnelSet = fmt.Errorf("tunnel already set")
//
//// ErrStillDialing is returned when trying to open or accept a connection from the tunnel but the manager is still trying
//// to open the tunnel with a dialer. This would only be returned if a dialer was set, i.e. creating a manager with
//// NewManagerWithDialer.
//var ErrStillDialing = fmt.Errorf("cannot access tunnel yet, still dialing")
//
//// TODO just change this to "Tunnel"?
//type Tunnel interface {
//	Open(context.Context) (net.Conn, error)
//	Listener(context.Context) (net.Listener, error)
//}
//
//type manager struct {
//	dialer Dialer
//
//	openConnection   chanutil.Service[*tls.Config, net.Conn]
//	addListener      chanutil.Service[struct{}, *listener]
//	addErrorListener chanutil.Service[struct{}, chan error]
//}
//
//// NewTunnel returns an instance of the Manager interface that uses uses the given dialer to open connections
//// over the tunnel.
//func NewTunnel(ctx context.Context, dialer Dialer) Tunnel {
//	m := &manager{}
//	m.dialer = dialer
//
//	m.openConnection = chanutil.NewService[*tls.Config, net.Conn](1)
//	m.addListener = chanutil.NewService[struct{}, *listener](1)
//	m.addErrorListener = chanutil.NewService[struct{}, chan error](1)
//
//	go m.startStateLoop(ctx)
//	return m
//}
//
//// startStateLoop starts the loop to accept requests over the channels used to synchronously access the manager's state.
//// Access the manager's state this way ensures we don't run into deadlocks or race conditions when a tunnel is used for
//// both opening and accepting connections.
//func (m *manager) startStateLoop(ctx context.Context) {
//	var tunnelErrs chan struct{}
//	var errListeners []chan error
//	var tun *tunnel
//
//	defer func() {
//		for _, errorListener := range errListeners {
//			close(errorListener)
//		}
//
//		if tun != nil {
//			if err := tun.Close(); err != nil {
//				log.WithError(err).Error("failed to close the tunnel")
//			}
//		}
//	}()
//
//	if tun == nil {
//		var err error
//		tun, err = m.dialer.Dial()
//		if err != nil {
//			log.WithError(err).Error("failed to dial tunnel")
//			writeOutError(errListeners, err)
//			return
//		}
//	}
//	tun.errCh()
//	defer m.openConnection.Close()
//	defer m.addListener.Close()
//	defer m.addErrorListener.Close()
//
//	for {
//		var err error
//
//		select {
//		case openConnection := <-m.openConnection.Listen():
//			log.Debug("Received request open a new connection.")
//			m.handleOpenConnection(tun, openConnection)
//		case addListener := <-m.addListener.Listen():
//			log.Debug("Received request for a new listener.")
//			m.handleAddListener(tun, addListener)
//		case addErrListener := <-m.addErrorListener.Listen():
//			log.Debug("Received request to add a new err listener.")
//
//			errListener := make(chan error)
//			errListeners = append(errListeners, errListener)
//			addErrListener.Return(errListener)
//		case <-tunnelErrs:
//			log.Debug("Received a tunnel error.")
//			if tun != nil {
//				err = tun.LastErr
//			}
//		case <-ctx.Done():
//			return
//		}
//
//		if err != nil {
//			log.WithError(err).Debug("Handling error.")
//
//			writeOutError(errListeners, err)
//			if err == ErrTunnelClosed {
//				// If there's no dialer exit the loop to reset and wait for a new tunnel to be set.
//				if m.dialer == nil {
//					continue
//				}
//
//				// This means there's a dialer set the tunnel to nil so we trigger that block that dials for a new tunnel.
//				tun = nil
//			}
//		}
//	}
//}
//
//func writeOutError(listeners []chan error, err error) {
//	for _, listener := range listeners {
//		select {
//		case listener <- err:
//		default:
//		}
//	}
//}
//
//// handleOpenConnection is used by the state loop to handle a request to open a connection over the tunnel
//func (*manager) handleOpenConnection(tun *tunnel, req chanutil.Request[*tls.Config, net.Conn]) {
//	defer req.Close()
//	log.Debug("Handling opening a connection over the tunnel.")
//
//	conn, err := tun.Open()
//	if err != nil {
//		req.ReturnError(err)
//	}
//
//	tlsCfg := req.Get()
//	if tlsCfg != nil {
//		conn = tls.Client(conn, tlsCfg)
//	}
//
//	log.Debug("Connection was opened.")
//	req.Return(conn)
//}
//
//// handleAddListener is used by the request loop to handle a request to retrieve a listener listening over the tunnel
//func (m *manager) handleAddListener(tun *tunnel, req chanutil.Request[struct{}, *listener]) {
//	defer req.Close()
//
//	log.Debug("Handling add a new listener.")
//
//	conResults := make(chan interface{})
//	req.Return(&listener{
//		conns: conResults,
//		done:  tun.AcceptWithChannel(conResults),
//		addr:  tun.Addr(),
//	})
//}
//
//// Open opens a connection over the tunnel
//func (m *manager) Open(ctx context.Context) (net.Conn, error) {
//	return m.openConnection.Send(ctx, nil)
//}
//
//// Listener retrieves a listener listening on the tunnel for connections
//func (m *manager) Listener(ctx context.Context) (net.Listener, error) {
//	return m.addListener.Send(ctx, struct{}{})
//}
