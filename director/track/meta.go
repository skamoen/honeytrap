// +build lxc

package track

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/sniffer"
)

// housekeeper handles the needed process of handling internal logic
// in maintaining the provided lxc.Container.
func (c *containerMeta) housekeeper(ctx context.Context) {
	// container lifetime function
	log.Infof("Housekeeper (%s) started.", c.name)
	defer log.Infof("Housekeeper (%s) stopped.", c.name)

	for {
		select {
		case <-ctx.Done():
			log.Infof("Container %s: stopping", c.name)
			c.c.Stop()
			return
		case <-time.After(time.Duration(c.delays.HousekeeperDelay)):
			if time.Since(c.idle) > time.Duration(c.delays.StopDelay) {
				log.Debugf("Container %s: idle for %s, stopping", c.name, time.Now().Sub(c.idle).String())
				c.c.Stop()
				c.d.activeContainers.Delete(c.name)

				if !c.c.Running() {
					return
				} else {
					log.Errorf("Container %s still running after stop call")
				}
			}
		}
	}
}

// Dial attempts to connect to the internal network of the
// internal container.
func (c *containerMeta) DialContainer(network string, port int) (net.Conn, error) {
	host := net.JoinHostPort(c.ip.String(), fmt.Sprintf("%d", port))
	retries := 0
	for {
		conn, err := net.Dial(network, host)
		if err == nil {
			return conn, nil
		}

		if retries < 50 {
			log.Debugf("Waiting for container to be fully started %s (%s)", c.name, err.Error())
			time.Sleep(time.Millisecond * 200)
			retries++
			continue
		}

		return nil, fmt.Errorf("could not connect to container")
	}
}
func (c *containerMeta) start() error {
	log.Debugf("Starting Container %s")

	c.idle = time.Now()
	go c.housekeeper(context.Background())

	err := c.c.WantDaemonize(true)
	if err != nil {
		return err
	}

	err = c.c.Start()
	if err != nil {
		return err
	}
	c.d.eb.Send(director.ContainerStartedEvent(c.name))
	return nil
}

func (c *containerMeta) getNetwork() error {
	retries := 0
	for {
		ip, err := c.c.IPAddress("eth0")
		if err == nil {
			log.Debugf("Got ip: %s", ip[0])
			c.ip = net.ParseIP(ip[0])
			break
		}

		if retries < 50 {
			time.Sleep(time.Millisecond * 200)
			retries++
			continue
		}

		return fmt.Errorf("Could not get an IP address")
	}

	var isets []string
	netws := c.c.ConfigItem("lxc.net")
	for ind := range netws {
		itypes := c.c.RunningConfigItem(fmt.Sprintf("lxc.net.0.%d.type", ind))
		if itypes == nil {
			continue
		}

		if itypes[0] == "veth" {
			isets = c.c.RunningConfigItem(fmt.Sprintf("lxc.net.0.%d.veth.pair", ind))
			break
		} else {
			isets = c.c.RunningConfigItem(fmt.Sprintf("lxc.net.0.%d.link", ind))
			break
		}
	}

	if len(isets) == 0 {
		return fmt.Errorf("could not get an network device")
	}

	c.idevice = isets[0]

	log.Debugf("Using network device %s to %s", c.idevice, c.name)

	c.idle = time.Now()

	c.sniffer = sniffer.New("")
	if err := c.sniffer.Start(c.idevice); err != nil {
		log.Errorf("Error occurred while attaching sniffer for %s to %s: %s", c.name, c.idevice, err.Error())
	}

	return nil
}
