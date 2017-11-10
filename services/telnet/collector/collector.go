package collector

import (
	"bytes"
	"net"
	"time"

	"github.com/honeytrap/honeytrap/pushers"
	telnet "github.com/honeytrap/honeytrap/services/telnet/util"
	"golang.org/x/sync/syncmap"
)

type Collector struct {
	negotiations [][]*negotiateCommand
	connections  *syncmap.Map // map[local][remote]:amount
	sessions     *syncmap.Map // map[remote]:*Session
	c            pushers.Channel
}

// New returns a new Collector
func New() *Collector {
	c := &Collector{}
	c.connections = new(syncmap.Map)
	return c
}

// RegisterConnection stores the incoming connection attempt and checks if this IP has been observed before
func (c *Collector) RegisterConnection(conn net.Conn) *telnet.Session {
	// TODO(skamoen): Check if an open session already exists
	// Create a session to store things in
	s := &telnet.Session{
		StartTime:   time.Now(),
		RemoteAddr:  conn.RemoteAddr(),
		LocalAddr:   conn.LocalAddr(),
		Negotiation: new(telnet.Negotiation),
		Credentials: new(telnet.Credentials),
	}

	localHost, _, _ := net.SplitHostPort(s.LocalAddr.String())
	remoteHost, _, _ := net.SplitHostPort(s.RemoteAddr.String())

	i, _ := c.connections.LoadOrStore(localHost, new(syncmap.Map))
	localHostMap := i.(*syncmap.Map)
	i, loaded := localHostMap.LoadOrStore(remoteHost, 1)
	if loaded {
		count := i.(int)
		localHostMap.Store(remoteHost, count+1)
	}
	return s
}

// SubmitNegotiation saves a completed negotiation result
func (c *Collector) SubmitNegotiation(n *telnet.Negotiation) {
	pn := parseCommands(n)
	seenBefore := checkNegotiation(c.negotiations, pn)
	if seenBefore {
		n.SeenBefore = true
	} else {
		c.negotiations = append(c.negotiations, pn)
	}
}

func parseCommands(n *telnet.Negotiation) []*negotiateCommand {
	commands := make([]*negotiateCommand, 0)

	split := bytes.Split(n.Bytes, []byte{telnet.IAC})

	for _, c := range split {
		if len(c) > 1 {
			command := &negotiateCommand{
				option:  c[0],
				command: c[1],
			}

			if c[1] == telnet.SubNegotiationStart || len(c) > 2 {
				command.subcommands = c[2:]
			}
			commands = append(commands, command)
		}
	}

	return commands
}

func checkNegotiation(negotiations [][]*negotiateCommand, n []*negotiateCommand) bool {
	for _, negotiation := range negotiations {
		if len(negotiation) == len(n) {
			for index, command := range negotiation {
				if command.option == n[index].option &&
					command.command == n[index].command &&
					bytes.Compare(command.subcommands, n[index].subcommands) == 0 {
					return true
				}
			}
		}
	}
	return false
}

type negotiateCommand struct {
	option      byte
	command     byte
	subcommands []byte
}
