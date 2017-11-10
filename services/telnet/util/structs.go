package util

import (
	"net"
	"time"
)

type Session struct {
	Negotiation *Negotiation
	Credentials *Credentials
	Interaction *Interaction
	StartTime   time.Time
	Duration    int
	RemoteAddr  net.Addr
	LocalAddr   net.Addr
	Raw         bool
}

// Negotiation is the Telnet Negotiation data from the beginning of a session
type Negotiation struct {
	Bytes                        []byte
	CommandEcho, CommandLinemode bool
	ValueEcho, ValueLinemode     bool
	SeenBefore                   bool
}

type Credentials struct {
	Input                         []byte
	InputTimes                    []int64
	Usernames, Passwords, Entries []string
}

type Interaction struct {
	Input      []byte
	InputTimes []int64
	Commands   []string
}
