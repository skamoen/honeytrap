// +build lxc

package track

import (
	"fmt"
	"net"
	"sync"
	"time"

	lxc "gopkg.in/lxc/go-lxc.v2"

	"github.com/honeytrap/honeytrap/pushers"
	"golang.org/x/sync/syncmap"
)

type trackDirector struct {
	Template         string `toml:"template"`
	eb               pushers.Channel
	activeContainers *syncmap.Map // map[string]*lxcContainer
	lxcCh            chan interface{}
}

type containerMeta struct {
	c *lxc.Container
	m sync.Mutex

	d      *trackDirector
	name   string
	eb     pushers.Channel
	lxcCh  chan interface{}
	delays Delays

	idle    time.Time
	ip      net.IP
	idevice string
	//sniffer  *sniffer.Sniffer
	template string
}

type Delays struct {
	StopDelay        Delay `toml:"stop_every"`
	HousekeeperDelay Delay `toml:"housekeeper_every"`
}

// Delay defines a duration type.
type Delay time.Duration

// Duration returns the type of the giving duration from the provided pointer.
func (t *Delay) Duration() time.Duration {
	return time.Duration(*t)
}

// trackContainerConn defines a custom connection type which proxies the data
// for the meta.
type trackContainerConn struct {
	net.Conn
	meta *containerMeta
}

// Read reads the giving set of data from the meta connection to the
// byte slice.
func (c trackContainerConn) Read(b []byte) (n int, err error) {
	c.meta.stillActive()
	return c.Conn.Read(b)
}

// Write writes the data into byte slice from the meta.
func (c trackContainerConn) Write(b []byte) (n int, err error) {
	c.meta.stillActive()
	return c.Conn.Write(b)
}

// stillActive returns an error if the containerr is not still active
func (c *containerMeta) stillActive() error {
	if !c.c.Running() {
		return fmt.Errorf("lxccontainer not running %s", c.name)
	}
	c.idle = time.Now()
	return nil
}
