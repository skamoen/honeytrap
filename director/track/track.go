// +build lxc

package track

import (
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/op/go-logging"
	"golang.org/x/sync/syncmap"
	"gopkg.in/lxc/go-lxc.v2"
)

var (
	_   = director.Register("track", New)
	log = logging.MustGetLogger("director/track")
)

func New(options ...func(director.Director) error) (director.Director, error) {
	d := &trackDirector{
		eb:       pushers.MustDummy(),
		lxcCh:    make(chan interface{}),
		Template: "honeytrap",
	}

	for _, optionFn := range options {
		optionFn(d)
	}

	d.activeContainers = &syncmap.Map{} // map[string]*containerMeta{}
	//go d.HandleLxcCommands()
	return d, nil
}

func (d *trackDirector) Dial(conn net.Conn) (net.Conn, error) {
	meta, err := d.getContainerMeta(conn)
	if err != nil {
		return nil, err
	}

	meta.m.Lock()
	defer meta.m.Unlock()
	if !meta.c.Running() {
		// Start the container and get network info
		err := meta.start()
		if err != nil {
			return nil, err
		}
		err = meta.getNetwork()
		if err != nil {
			return nil, err
		}
	}

	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		connection, err := meta.DialContainer("tcp", ta.Port)
		return trackContainerConn{Conn: connection, meta: meta}, err
	} else {
		return nil, errors.New("Unsupported protocol")
	}

}

func (d *trackDirector) getContainerMeta(conn net.Conn) (*containerMeta, error) {
	// Currently, only check on Remote Addr hash
	name := d.getContainerName(conn)

	// Get meta from cache, or store a clean one
	m, found := d.activeContainers.LoadOrStore(name, &containerMeta{
		d:        d,
		name:     name,
		eb:       d.eb,
		lxcCh:    d.lxcCh,
		idle:     time.Time{},
		template: d.Template,
		delays: Delays{
			StopDelay:        Delay(2 * time.Minute),
			HousekeeperDelay: Delay(30 * time.Second),
		},
	})

	meta := m.(*containerMeta)

	if !found {
		// Container not in cache, check state
		meta.m.Lock()
		defer meta.m.Unlock()

		handle, exists := d.checkExists(name)
		if !exists {
			// Container doesn't exist yet, create a new one from template
			cloneHandle, err := d.cloneWithName(name)
			if err != nil {
				return nil, err
			}
			meta.c = cloneHandle
		} else {
			meta.c = handle
		}
	}
	return meta, nil
}

func (d *trackDirector) cloneWithName(name string) (*lxc.Container, error) {
	templateHandle, err := lxc.NewContainer(d.Template)
	if err != nil {
		return nil, err
	}

	defer lxc.Release(templateHandle)

	// Attempt to clone the meta
	if err = templateHandle.Clone(name, lxc.CloneOptions{
		Backend:  lxc.Overlayfs,
		Snapshot: true,
		KeepName: true,
	}); err != nil {
		return nil, err
	}

	newContainerHandle, err := lxc.NewContainer(name)
	if err != nil {
		return nil, err
	}

	newContainerHandle.SetConfigItem("lxc.console.path", "none")
	newContainerHandle.SetConfigItem("lxc.tty.max", "0")
	newContainerHandle.SetConfigItem("lxc.cgroup.devices.deny", "c 5:1 rwm")

	d.eb.Send(director.ContainerClonedEvent(name, d.Template))
	return newContainerHandle, err
}

func (d *trackDirector) checkExists(name string) (*lxc.Container, bool) {
	containerHandle, err := lxc.NewContainer(name)
	if err != nil {
		return nil, false
	}
	return containerHandle, true
}

func (d *trackDirector) getContainerName(conn net.Conn) string {
	// RemoteAddr hash-based function
	h := fnv.New32()
	remoteAddr, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	//localAddr, _, _ := net.SplitHostPort(conn.LocalAddr().String())
	h.Write([]byte(remoteAddr))
	//h.Write([]byte(localAddr))
	hash := h.Sum(nil)
	name := fmt.Sprintf("firmware-%s", hex.EncodeToString(hash))
	return name
}
