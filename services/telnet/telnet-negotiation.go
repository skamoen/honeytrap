package telnet

import (
	"net"
	"time"

	u "github.com/honeytrap/honeytrap/services/telnet/util"
	"github.com/op/go-logging"
)

func (s *telnetService) negotiateTelnet(conn net.Conn) (*u.Negotiation, error) {
	log = logging.MustGetLogger("services/telnet/negotiation")

	log.Debugf("Starting negotiation: %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	negotiation := &u.Negotiation{}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Write IAC DO LINE MODE IAC WILL ECH
	_, err := conn.Write([]byte{u.IAC, u.Do, u.Linemode, u.IAC, u.Will, u.Echo})
	if err != nil {
		log.Errorf("Error writing initial negotiation: %s => %s: %s", conn.RemoteAddr().String(), conn.LocalAddr().String(), err.Error())
	}

	var buffer [1]byte
	_, err = conn.Read(buffer[0:])
	if err != nil {
		log.Errorf("Error reading connection on negotiate init: %s => %s: %s", conn.RemoteAddr().String(), conn.LocalAddr().String(), err.Error())
		negotiation.Valid = false
		return negotiation, err
	}

	negotiation.Bytes = append(negotiation.Bytes, buffer[0])

	// IAC, start of command
	if buffer[0] == u.IAC {
		var option byte
		validOption := false

		for {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			// Read next byte, expect option
			_, err := conn.Read(buffer[0:])
			if err != nil {
				log.Errorf("Error reading connection: %s : %s => %s", err.Error(), conn.RemoteAddr().String(), conn.LocalAddr().String())
				return negotiation, err
			}
			negotiation.Bytes = append(negotiation.Bytes, buffer[0])

			// If null byte, try again
			if buffer[0] == 0 {
				continue
			}

			if buffer[0] == u.IAC {
				// New Command, reset and read new byte
				option = 0
				validOption = false
				continue
			}
			// DO, WILL, WONT, DONT
			if buffer[0] == u.Do || buffer[0] == u.Will || buffer[0] == u.Wont || buffer[0] == u.Dont {
				// Option is a valid Telnet option
				option = buffer[0]
				validOption = true
				continue
			}

			// ECHO
			if buffer[0] == u.Echo {
				if validOption {
					negotiation.CommandEcho = true
					if option == u.Do {
						negotiation.ValueEcho = true
					}
				}
			}
			// LINEMODE close the socket
			if buffer[0] == u.Linemode {
				if validOption {
					negotiation.CommandLinemode = true
					if option == u.Will {
						negotiation.ValueLinemode = true
					}
				}
			}

			if negotiation.CommandEcho && negotiation.CommandLinemode {
				negotiation.Valid = true
				break
			}
		}
	}
	return negotiation, nil
}
