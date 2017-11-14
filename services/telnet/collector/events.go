package collector

import (
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/services/telnet/util"
)

func (col *Collector) LogNegotiation(n *util.Negotiation) {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(n.Bytes))
	for i, b := range n.Bytes {
		bytes[i] = int(b)
	}
	col.c.Send(event.New(
		event.Service("telnet"),
		event.Category("session"),
		event.Type("negotiation"),
		event.DestinationAddr(n.Session.LocalAddr),
		event.SourceAddr(n.Session.RemoteAddr),

		event.Custom("bytes", bytes),
		event.Custom("echo", n.ValueEcho),
		event.Custom("linemode", n.ValueLinemode),
	))
}

func (col *Collector) LogCredentials(c *util.Credentials) {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(c.Input))
	for i, b := range c.Input {
		bytes[i] = int(b)
	}

	col.c.Send(event.New(
		event.Service("telnet"),
		event.Category("session"),
		event.Type("credentials"),
		event.DestinationAddr(c.Session.LocalAddr),
		event.SourceAddr(c.Session.RemoteAddr),

		event.Custom("input_bytes", bytes),
		event.Custom("input_times", c.InputTimes),
		event.Custom("usernames", c.Usernames),
		event.Custom("passwords", c.Passwords),
		event.Custom("entries", c.Entries),
	))
}

func (col *Collector) LogInteraction(i *util.Interaction) {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(i.Input))
	for j, b := range i.Input {
		bytes[j] = int(b)
	}
	col.c.Send(event.New(
		event.Service("telnet"),
		event.Category("session"),
		event.Type("commands"),
		event.DestinationAddr(i.Session.LocalAddr),
		event.SourceAddr(i.Session.RemoteAddr),
	))
}
