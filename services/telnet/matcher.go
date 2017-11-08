package telnet

import (
	"bytes"
	"net"

	"golang.org/x/sync/syncmap"
)

var (
	negotiations [][]*negotiateCommand
	connections  = new(syncmap.Map)
	// connections  = make(map[string]map[string]int, 0)
)

type negotiateCommand struct {
	option      byte
	command     byte
	subcommands []byte
}

func SubmitNegotiation(n *Negotiation, id int) {
	pn := parseCommands(n)
	seenBefore := checkNegotiation(pn)
	if seenBefore {
		n.seenBefore = true
	} else {
		negotiations = append(negotiations, pn)
	}
}

func parseCommands(n *Negotiation) []*negotiateCommand {
	commands := make([]*negotiateCommand, 0)

	split := bytes.Split(n.Bytes, []byte{IAC})

	for _, c := range split {
		if len(c) > 1 {
			command := &negotiateCommand{
				option:  c[0],
				command: c[1],
			}

			if c[1] == SubNegotiationStart || len(c) > 2 {
				command.subcommands = c[2:]
			}
			commands = append(commands, command)
		}
	}

	return commands
}

func checkNegotiation(n []*negotiateCommand) bool {
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

// RegisterConnection stores the incoming connection attempt and checks if this IP has been observed before
func RegisterConnection(local, remote net.Addr) {
	localHost, _, _ := net.SplitHostPort(local.String())
	remoteHost, _, _ := net.SplitHostPort(remote.String())

	i, _ := connections.LoadOrStore(localHost, new(syncmap.Map))
	localHostMap := i.(*syncmap.Map)
	i, loaded := localHostMap.LoadOrStore(remoteHost, 1)
	if loaded {
		count := i.(int)
		localHostMap.Store(remoteHost, count+1)
	}
}
