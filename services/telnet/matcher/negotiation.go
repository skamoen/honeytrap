package matcher

import (
	"github.com/honeytrap/honeytrap/services/telnet"
)

var (
	negotiations []*telnet.Negotiation
)

type negotiateCommands struct {
}

func SubmitNegotiation(n *telnet.Negotiation, id int) {
	negotiations = append(negotiations, n)
}

func parseCommands(n *telnet.Negotiation) []negotiateCommands {

	return nil
}
