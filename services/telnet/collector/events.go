package collector

import (
	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/services/telnet/util"
)

func (c *Collector) LogNegotiation(n *util.Negotiation) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("negotiation"),
		event.DestinationAddr(n.Session.LocalAddr),
		event.SourceAddr(n.Session.RemoteAddr),

		event.Custom("bytes", convertBytes(n.Bytes)),
		event.Custom("echo", n.ValueEcho),
		event.Custom("linemode", n.ValueLinemode),
	))
}

func (c *Collector) LogCredentials(cr *util.Credentials) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("credentials"),
		event.DestinationAddr(cr.Session.LocalAddr),
		event.SourceAddr(cr.Session.RemoteAddr),

		event.Custom("input_bytes", convertBytes(cr.Input)),
		event.Custom("input_times", cr.InputTimes),
		event.Custom("usernames", cr.Usernames),
		event.Custom("passwords", cr.Passwords),
		event.Custom("entries", cr.Entries),
	))
}

func (c *Collector) LogInteraction(i *util.Interaction) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("commands"),
		event.DestinationAddr(i.Session.LocalAddr),
		event.SourceAddr(i.Session.RemoteAddr),

		event.Custom("input_bytes", convertBytes(i.Input)),
		event.Custom("input_times", i.InputTimes),
		event.Custom("commands", i.Commands),
	))
}

func (c *Collector) LogSession(s *util.Session) {
	c.c.Send(event.New(
		event.Service("telnet"),
		event.Type("session"),
		event.DestinationAddr(s.LocalAddr),
		event.SourceAddr(s.RemoteAddr),

		// event.Custom("duration", s.Duration),
		// event.Custom("start_time", s.StartTime),
		// event.Custom("raw", s.Raw),

		// event.Custom("negotiation", s.Negotiation),
		// event.Custom("credentials", s.Credentials),
		// event.Custom("commands", s.Interaction),
	))
}

func convertBytes(i []byte) []int {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(i))
	for j, b := range i {
		bytes[j] = int(b)
	}

	return bytes
}
