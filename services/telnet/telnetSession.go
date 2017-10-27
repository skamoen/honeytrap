package telnet

import (
	"net"
	"time"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"
)

type Session struct {
	Negotiation *Negotiation
	Metrics     *Metrics
	Raw         bool
	StartTime   time.Time
	ID          int
	Duration    int
	RemoteAddr  net.Addr
	LocalAddr   net.Addr
}

type Metrics struct {
	Input      []byte
	InputTimes []int64
	Usernames  []string
	Passwords  []string
	Entries    []string
}

// Negotiation is the Telnet Negotiation data from the beginning of a session
type Negotiation struct {
	Bytes                        []byte
	CommandEcho, CommandLinemode bool
	ValueEcho, ValueLinemode     bool
}

func (s *Session) LogMetrics(c pushers.Channel) {
	metricsMap := map[string]interface{}{
		"raw":              s.Raw,
		"session_start":    s.StartTime,
		"session_duration": time.Since(s.StartTime) / 1000000,
		"input_bytes":      s.Metrics.Input,
		"input_times":      s.Metrics.InputTimes,
		"usernames":        s.Metrics.Usernames,
		"passwords":        s.Metrics.Passwords,
		"entries":          s.Metrics.Entries,
	}

	c.Send(event.New(
		event.Service("telnet"),
		event.Category("session"),
		event.Type("metrics"),
		event.DestinationAddr(s.LocalAddr),
		event.SourceAddr(s.RemoteAddr),
		event.CopyFrom(metricsMap),
	))
}

func (s *Session) LogNegotiation(c pushers.Channel) {
	c.Send(event.New(
		event.Service("telnet"),
		event.Category("session"),
		event.Type("negotiation"),
		event.DestinationAddr(s.LocalAddr),
		event.SourceAddr(s.RemoteAddr),
		event.Custom("bytes", s.Negotiation.Bytes),
		event.Custom("echo", s.Negotiation.ValueEcho),
		event.Custom("linemode", s.Negotiation.ValueLinemode),
	))
}