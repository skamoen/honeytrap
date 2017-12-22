package collector

import (
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/services/telnet/util"
)

// LogNegotiation logs the negotiation for a session
func (c *Collector) LogNegotiation(n *util.Negotiation) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("negotiation"),
		event.DestinationAddr(n.Session.LocalAddr),
		event.SourceAddr(n.Session.RemoteAddr),
		event.Custom("agent-ip", n.Session.AgentAddr),
		event.CopyFrom(n.ToMap()),
	))
}

// LogCredentials logs all credentials used
func (c *Collector) LogCredentials(cr *util.Credentials) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("credentials"),
		event.DestinationAddr(cr.Session.LocalAddr),
		event.SourceAddr(cr.Session.RemoteAddr),
		event.Custom("agent-ip", cr.Session.AgentAddr),
		event.CopyFrom(cr.ToMap()),
	))
}

// LogInteraction fires an event containing all commands
func (c *Collector) LogInteraction(i *util.Interaction) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("commands"),
		event.DestinationAddr(i.Session.LocalAddr),
		event.SourceAddr(i.Session.RemoteAddr),
		event.Custom("agent-ip", i.Session.AgentAddr),
		event.CopyFrom(i.ToMap()),
	))
}

// LogSession logs the full session, including the Negotiation, Credentials and Commands.
func (c *Collector) LogSession(s *util.Session) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("session"),
		event.DestinationAddr(s.LocalAddr),
		event.SourceAddr(s.RemoteAddr),
		event.Custom("agent-ip", s.AgentAddr),
		event.CopyFrom(s.ToMap()),
	))
}
