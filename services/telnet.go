/*
* Honeytrap
* Copyright (C) 2016-2017 DutchSec (https://dutchsec.com/)
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU Affero General Public License version 3 as published by the
* Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public License for more
* details.
*
* You should have received a copy of the GNU Affero General Public License
* version 3 along with this program in the file "LICENSE".  If not, see
* <http://www.gnu.org/licenses/agpl-3.0.txt>.
*
* See https://honeytrap.io/ for more details. All requests should be sent to
* licensing@honeytrap.io
*
* The interactive user interfaces in modified source and object code versions
* of this program must display Appropriate Legal Notices, as required under
* Section 5 of the GNU Affero General Public License version 3.
*
* In accordance with Section 7(b) of the GNU Affero General Public License version 3,
* these Appropriate Legal Notices must retain the display of the "Powered by
* Honeytrap" logo and retain the original copyright notice. If the display of the
* logo is not reasonably feasible for technical reasons, the Appropriate Legal Notices
* must display the words "Powered by Honeytrap" and retain the original copyright notice.
 */
package services

import (
	"bytes"
	"io"
	"net"
	"strings"
	"time"

	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services/telnet"
)

var (
	_ = Register("telnet", Telnet)
)

// Telnet is a placeholder
func Telnet(options ...ServicerFunc) Servicer {
	s := &telnetService{}
	for _, o := range options {
		o(s)
	}
	return s
}

type telnetService struct {
	c pushers.Channel
}

func (s *telnetService) SetChannel(c pushers.Channel) {
	s.c = c
}

func (s *telnetService) Handle(conn net.Conn) error {
	defer conn.Close()

	for {
		line, err := b.ReadBytes('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			log.Error(err.Error())
			continue
		}
		lastInput = time.Now()
	}
}

func handleNewline(conn net.Conn, state [3]string, input *bytes.Buffer, metrics *telnet.Metrics) [3]string {
	if state[0] == "username" {
		// Read all characters in the buffer
		state[1] = input.String()
		metrics.Usernames = append(metrics.Usernames, state[1])

		// Clear the buffer
		input.Reset()

		// Switch to password entry
		state[0] = "password"
		conn.Write([]byte("\r\nPassword: "))
	} else {
		// Store all characters in the buffer
		state[2] = input.String()

		metrics.Passwords = append(metrics.Passwords, state[2])
		metrics.Entries = append(metrics.Entries, strings.Join(state[1:], ":"))

		// Reset the buffers and state
		input.Reset()
		state[0] = "username"
		state[1] = ""
		state[2] = ""

		conn.Write([]byte("\r\nWrong password!\r\n\r\nUsername: "))
	}
	return state
}

func negotiateTelnet(conn net.Conn) (*telnet.Negotiation, error) {
	negotiation := new(telnet.Negotiation)
	// Write IAC DO LINE MODE IAC WILL ECH
	conn.Write([]byte{telnet.IAC, telnet.Do, telnet.Linemode, telnet.IAC, telnet.Will, telnet.Echo})

	// Expect IAC WILL LINEMODE
	// Expect IAC DO ECHO

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// Read 3 bytes per read for commands
	var buffer [1]byte
	_, err := conn.Read(buffer[0:])
	if err != nil {
		return negotiation, err
	}

	negotiation.Bytes = append(negotiation.Bytes, buffer[0])

	// IAC, start of command
	if buffer[0] == telnet.IAC {
		var option byte
		validOption := false

		for {
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			// Read next byte, expect option
			_, err := conn.Read(buffer[0:])
			if err != nil {
				return negotiation, err
			}
			negotiation.Bytes = append(negotiation.Bytes, buffer[0])

			// If null byte, try again
			if buffer[0] == 0 {
				continue
			}

			if buffer[0] == telnet.IAC {
				// New Command, reset and read new byte
				option = 0
				validOption = false
				continue
			}
			// DO, WILL, WONT, DONT
			if buffer[0] == telnet.Do || buffer[0] == telnet.Will || buffer[0] == telnet.Wont || buffer[0] == telnet.Dont {
				// Option is a valid Telnet option
				option = buffer[0]
				validOption = true
				continue
			}

			// ECHO
			if buffer[0] == telnet.Echo {
				if validOption {
					negotiation.CommandEcho = true
					if option == telnet.Do {
						negotiation.ValueEcho = true
					}
				}
			}
			// LINEMODE close the socket
			if buffer[0] == telnet.Linemode {
				if validOption {
					negotiation.CommandLinemode = true
					if option == telnet.Will {
						negotiation.ValueLinemode = true
					}
				}
			}

			if negotiation.CommandEcho && negotiation.CommandLinemode {
				break
			}
		}
	}
	return negotiation, nil
}
