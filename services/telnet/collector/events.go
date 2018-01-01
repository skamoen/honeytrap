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
		event.AgentAddr(n.Session.AgentAddr.AgentAddress()),
		event.AgentToken(n.Session.AgentAddr.AgentToken()),
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
		event.AgentAddr(cr.Session.AgentAddr.AgentAddress()),
		event.AgentToken(cr.Session.AgentAddr.AgentToken()),
		event.CopyFrom(cr.ToMap()),
	))
}

// LogInteraction fires an event containing all commands
func (c *Collector) LogInteraction(i *util.Interaction) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("commands"),
		event.DestinationAddr(i.Session.LocalAddr),
		event.AgentAddr(i.Session.AgentAddr.AgentAddress()),
		event.AgentToken(i.Session.AgentAddr.AgentToken()),
		event.CopyFrom(i.ToMap()),
	))
}

// LogSession logs the full session, including the Negotiation, Credentials and Commands.
func (c *Collector) LogSession(s *util.Session) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("session"),
		event.DestinationAddr(s.LocalAddr),
		event.AgentAddr(s.AgentAddr.AgentAddress()),
		event.AgentToken(s.AgentAddr.AgentToken()),
		event.CopyFrom(s.ToMap()),
	))
}
