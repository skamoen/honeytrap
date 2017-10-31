package telnet

import (
	"bytes"
	"fmt"
	"net"
)

var (
	negotiations [][]*negotiateCommand
	connections  = make(map[string]map[string]int, 0)
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
		fmt.Println("Negotiation seen before!")
	} else {
		negotiations = append(negotiations, pn)
	}
}

func parseCommands(n *Negotiation) []*negotiateCommand {
	commands := make([]*negotiateCommand, 0)

	split := bytes.Split(n.Bytes, []byte{IAC})

	for _, c := range split {
		if len(c) > 0 {
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
		for index, command := range negotiation {
			if command.option == n[index].option &&
				command.command == n[index].command &&
				bytes.Compare(command.subcommands, n[index].subcommands) == 0 {
				return true
			}
		}
	}
	return false
}

// RegisterConnection stores the incoming connection attempt and checks if this IP has been observed before
func RegisterConnection(local, remote net.Addr) {
	localHost, _, _ := net.SplitHostPort(local.String())
	remoteHost, _, _ := net.SplitHostPort(remote.String())
	if connections[localHost] == nil {
		// Never saw a connection to this local IP
		connections[localHost] = make(map[string]int, 1)
		// Register the remote address
		localAddress := connections[localHost]
		localAddress[remoteHost] = 1
	} else {
		fmt.Println("Connection seen before")
		localAddress := connections[localHost]
		localAddress[remoteHost]++
	}

}
