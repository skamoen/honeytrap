package proxies

import (
	"net"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers"
)

// ProxyListener defines a struct which holds a giving net.Listener.
type ProxyListener struct {
	net.Listener
	director *director.Director
	pusher   *pushers.Pusher
	events   *pushers.EventDelivery
}

// NewProxyListener returns a new instance for a ProxyListener.
func NewProxyListener(l net.Listener, d *director.Director, p *pushers.Pusher, e *pushers.EventDelivery) *ProxyListener {
	return &ProxyListener{
		l,
		d,
		p,
		e,
	}
}

// Accept returns a new net.Conn from the underline Proxy Listener.
func (lw *ProxyListener) Accept() (c net.Conn, err error) {
	c, err = lw.Listener.Accept()
	if err != nil {

		lw.events.Deliver(EventConnectionError(lw.Listener.Addr(), "ProxyConn", err))

		return nil, err
	}

	lw.events.Deliver(EventConnectionOpened(c.LocalAddr(), "ProxyConn", nil))

	container, err := lw.director.GetContainer(c)
	if err != nil {
		lw.events.Deliver(EventConnectionError(c.LocalAddr(), "ProxyConn", err))
		lw.events.Deliver(EventConnectionClosed(c.LocalAddr(), "ProxyConn", err))
		c.Close()
		return nil, err
	}

	_, port, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		lw.events.Deliver(EventConnectionClosed(c.LocalAddr(), "ProxyConn", err))
		c.Close()
		return nil, err
	}

	log.Debugf("Connecting to container port: %s", port)

	var c2 net.Conn
	c2, err = container.Dial(port)
	if err != nil {
		lw.events.Deliver(EventConnectionClosed(c.LocalAddr(), "ProxyConn", err))
		c.Close()
		return nil, err
	}

	return &ProxyConn{c, c2, container, lw.pusher, lw.events}, err
}

// Close closes the underline net.Listener.
func (lw *ProxyListener) Close() error {
	log.Info("Listener closed")

	lw.events.Deliver(EventConnectionClosed(lw.Addr(), "ProxyListener", nil))

	return lw.Listener.Close()
}

// Addr returns the underline address of the internal net.Listener.
func (lw *ProxyListener) Addr() net.Addr {
	return lw.Listener.Addr()
}
