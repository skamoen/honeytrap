package matcher

import (
	"bytes"
	"fmt"

	"github.com/honeytrap/honeytrap/services/telnet"
)

var (
	negotiations [][]*negotiateCommand
)

type negotiateCommand struct {
	option      byte
	command     byte
	subcommands []byte
}

func SubmitNegotiation(n *telnet.Negotiation, id int) {
	pn := parseCommands(n)
	seenBefore := checkNegotiation(pn)
	if seenBefore {
		fmt.Println("Negotiation seen before!")
	} else {
		negotiations = append(negotiations, pn)
	}
}

func parseCommands(n *telnet.Negotiation) []*negotiateCommand {
	commands := make([]*negotiateCommand, 0)

	split := bytes.Split(n.Bytes, []byte{telnet.IAC})

	for _, c := range split {
		if len(c) > 0 {
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
