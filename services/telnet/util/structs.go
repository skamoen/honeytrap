package util

import (
	"net"
	"time"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/listener/agent"
)

type Session struct {
	Banner      string
	Negotiation *Negotiation
	Auth        *Auth
	Interaction *Interaction
	StartTime   time.Time
	Duration    int
	RemoteAddr  net.Addr
	LocalAddr   net.Addr
	AgentAddr   agent.AgentAddresser
	Raw         bool
}

func (s *Session) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"banner":      s.Banner,
		"negotiation": s.Negotiation.ToMap(),
		"credentials": s.Auth.ToMap(),
		"interaction": s.Interaction.ToMap(),
		"start_time":  s.StartTime,
		"duration":    s.Duration,
		"raw":         s.Raw,
	}
}

func (s *Session) EventOptions() event.Option {
	o := event.NewWith(
		event.Service("telnet"),
		event.DestinationAddr(s.LocalAddr),
		event.SourceAddr(s.RemoteAddr),
	)

	if s.AgentAddr != nil {
		o = event.NewWith(o,
			event.AgentAddr(s.AgentAddr.AgentAddress()),
			event.AgentToken(s.AgentAddr.AgentToken()),
		)
	}
	return o
}

type TelnetContainer struct {
	ContainerConnection net.Conn
	In                  chan []byte
}

// Negotiation is the Telnet Negotiation data from the beginning of a session
type Negotiation struct {
	Session                      *Session
	Bytes                        []byte
	CommandEcho, CommandLinemode bool
	ValueEcho, ValueLinemode     bool
	Valid                        bool
}

func (n *Negotiation) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"bytes":    convertBytes(n.Bytes),
		"linemode": n.ValueLinemode,
		"echo":     n.ValueEcho,
		"valid":    n.Valid,
	}
}

type Auth struct {
	Session                       *Session
	Input                         []byte
	InputTimes                    []int64
	Usernames, Passwords, Entries []string
	Success                       bool
	Root                          bool
}

func (c *Auth) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"input_bytes": convertBytes(c.Input),
		"input_times": c.InputTimes,
		"usernames":   c.Usernames,
		"passwords":   c.Passwords,
		"entries":     c.Entries,
		"success":     c.Success,
		"root":        c.Root,
	}
}

type Interaction struct {
	Session         *Session
	Input           []byte
	InputTimes      []int64
	Commands        []string
	TelnetContainer *TelnetContainer
}

func (i *Interaction) ToMap() map[string]interface{} {
	interaction := map[string]interface{}{
		"input_bytes": convertBytes(i.Input),
		"input_times": i.InputTimes,
		"commands":    i.Commands,
	}

	if i.TelnetContainer != nil {
		interaction["lxc_ip"] = i.TelnetContainer.ContainerConnection.RemoteAddr().String()
	}

	return interaction
}

func convertBytes(i []byte) []int {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(i))
	for j, b := range i {
		bytes[j] = int(b)
	}
	return bytes
}
