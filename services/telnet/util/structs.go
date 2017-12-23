package util

import (
	"net"
	"time"
)

type Session struct {
	Negotiation     *Negotiation
	Credentials     *Credentials
	Interaction     *Interaction
	TelnetContainer *TelnetContainer
	StartTime       time.Time
	Duration        int
	RemoteAddr      net.Addr
	LocalAddr       net.Addr
	AgentAddr       net.Addr
	Raw             bool
}

func (s *Session) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"negotiation": s.Negotiation.ToMap(),
		"credentials": s.Credentials.ToMap(),
		"interaction": s.Interaction.ToMap(),
		"start_time":  s.StartTime,
		"duration":    s.Duration,
		"raw":         s.Raw,
	}
}

type TelnetContainer struct {
	ContainerConnection *net.Conn
	RemoteConnection    *net.Conn
	ReplyChannel        chan byte
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

type Credentials struct {
	Session                       *Session
	Input                         []byte
	InputTimes                    []int64
	Usernames, Passwords, Entries []string
}

func (c *Credentials) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"input_bytes": convertBytes(c.Input),
		"input_times": c.InputTimes,
		"usernames":   c.Usernames,
		"passwords":   c.Passwords,
		"entries":     c.Entries,
	}
}

type Interaction struct {
	Session    *Session
	Input      []byte
	InputTimes []int64
	Commands   []string
}

func (i *Interaction) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"input_bytes": convertBytes(i.Input),
		"input_times": i.InputTimes,
		"commands":    i.Commands,
	}
}

func convertBytes(i []byte) []int {
	// Convert raw bytes to "readable" int values
	bytes := make([]int, len(i))
	for j, b := range i {
		bytes[j] = int(b)
	}
	return bytes
}
