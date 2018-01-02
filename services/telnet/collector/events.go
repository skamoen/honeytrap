package collector

import (
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/services/telnet/util"
)

// LogNegotiation logs the negotiation for a session
func (c *Collector) LogNegotiation(n *util.Negotiation) {

	c.c.Send(event.New(
		n.Session.EventOptions(),
		event.Type("negotiation"),
		event.CopyFrom(n.ToMap()),
	))
}

// LogCredentials logs all credentials used
func (c *Collector) LogCredentials(cr *util.Auth) {
	c.c.Send(event.New(
		cr.Session.EventOptions(),
		event.Type("credentials"),
		event.CopyFrom(cr.ToMap()),
	))
}

// LogInteraction fires an event containing all commands
func (c *Collector) LogInteraction(i *util.Interaction) {
	c.c.Send(event.New(
		i.Session.EventOptions(),
		event.Type("commands"),
		event.CopyFrom(i.ToMap()),
	))
}

// LogSession logs the full session, including the Negotiation, Auth and Commands.
func (c *Collector) LogSession(s *util.Session) {
	c.c.Send(event.New(
		s.EventOptions(),
		event.Type("session"),
		event.CopyFrom(s.ToMap()),
	))
}
