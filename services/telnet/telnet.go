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
package telnet

import (
	"bytes"
	"net"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"
)

var log = logging.MustGetLogger("services/telnet")
var ID = 0

var (
	_ = services.Register("telnet", Telnet)
)

// Telnet is a placeholder
func Telnet(options ...services.ServicerFunc) services.Servicer {
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
	RegisterConnection(conn.LocalAddr(), conn.RemoteAddr())
	banner := []byte("\nUser Access Verification\r\nUsername:")
	timeout := 30 * time.Second
	var err error

	ID++
	session := &Session{
		StartTime:   time.Now(),
		RemoteAddr:  conn.RemoteAddr(),
		LocalAddr:   conn.LocalAddr(),
		Metrics:     new(Metrics),
		Negotiation: new(Negotiation),
		ID:          ID,
	}
	// Save the current state, username and password
	state := [3]string{"username", "", ""}

	defer session.LogMetrics(s.c)

	// Negotiate linemode and echo. Results will be stored in the session.
	session.Negotiation, err = negotiateTelnet(conn)
	SubmitNegotiation(session.Negotiation, session.ID)
	session.LogNegotiation(s.c)

	// If telnet Negotiation fails, save the inputbytes as a raw session
	if err != nil {
		session.Raw = true
		session.Metrics.Input = append(session.Metrics.Input, session.Negotiation.Bytes...)
	}

	// Send the banner to the remote host
	conn.Write(banner)

	// Read one byte at a time
	var buf [1]byte
	var input bytes.Buffer
	lastInput := time.Now()

	for {
		conn.SetReadDeadline(time.Now().Add(timeout))

		n, err := conn.Read(buf[0:])
		if err != nil {
			// Read error, most likely time-out
			return nil
		}

		// Save the received input regardless of content
		session.Metrics.Input = append(session.Metrics.Input, buf[0])
		session.Metrics.InputTimes = append(session.Metrics.InputTimes, time.Since(lastInput).Nanoseconds()/1000000)

		switch buf[0] {
		case 127: // DEL
			fallthrough
		case 8: // Backspace
			// Only deal with Backspace if we're supposed to DO ECHO
			if session.Negotiation.ValueEcho {
				if input.Len() > 0 {
					// Remove the previous character from the buffer
					input.Truncate(input.Len() - 1)
					if state[0] == "username" && !session.Raw {
						// Remove the character at the remote host
						conn.Write([]byte("\b \b"))
					}
				}
			}
		case 0: // null
			fallthrough
		case 10: // New Line
			state = handleNewline(conn, state, &input, session.Metrics)
		case 13:
		default:
			if state[0] == "username" && !session.Raw {
				// Echo the character when in username mode
				if session.Negotiation.ValueEcho {
					_, err := conn.Write(buf[0:n])
					if err != nil {
					}
				}
			}
			// Store the input
			input.WriteByte(buf[0])
		}
		lastInput = time.Now()
	}
}

func handleNewline(conn net.Conn, state [3]string, input *bytes.Buffer, metrics *Metrics) [3]string {
	inputString := input.String()
	if strings.Contains(inputString, "/bin/busybox") {
		state[0] = "busybox"
		index := strings.Index(inputString, "x ")
		appName := inputString[index+2:]
		conn.Write([]byte("\r\n" + appName + ": applet not found\r\n~"))
		// fmt.Println("Found app", appName)
		return state
	}

	if state[0] == "username" {
		// Read all characters in the buffer
		state[1] = inputString
		metrics.Usernames = append(metrics.Usernames, state[1])

		// Clear the buffer
		input.Reset()

		// Switch to password entry
		state[0] = "password"
		conn.Write([]byte("\r\nPassword: "))
	} else {
		// Store all characters in the buffer
		state[2] = inputString

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

func negotiateTelnet(conn net.Conn) (*Negotiation, error) {
	negotiation := new(Negotiation)
	// Write IAC DO LINE MODE IAC WILL ECH
	conn.Write([]byte{IAC, Do, Linemode, IAC, Will, Echo})

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
	if buffer[0] == IAC {
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

			if buffer[0] == IAC {
				// New Command, reset and read new byte
				option = 0
				validOption = false
				continue
			}
			// DO, WILL, WONT, DONT
			if buffer[0] == Do || buffer[0] == Will || buffer[0] == Wont || buffer[0] == Dont {
				// Option is a valid Telnet option
				option = buffer[0]
				validOption = true
				continue
			}

			// ECHO
			if buffer[0] == Echo {
				if validOption {
					negotiation.CommandEcho = true
					if option == Do {
						negotiation.ValueEcho = true
					}
				}
			}
			// LINEMODE close the socket
			if buffer[0] == Linemode {
				if validOption {
					negotiation.CommandLinemode = true
					if option == Will {
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
