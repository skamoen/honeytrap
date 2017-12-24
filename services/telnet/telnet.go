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
	"bufio"
	"bytes"
	"net"
	"strings"
	"time"

	logging "github.com/op/go-logging"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/listener/agent"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"

	"github.com/honeytrap/honeytrap/services/telnet/collector"
	u "github.com/honeytrap/honeytrap/services/telnet/util"
	// Lazy import for util structs
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
	s.col = collector.New()
	s.col.SetChannel(s.c)
	return s
}

type telnetService struct {
	c                  pushers.Channel
	AllowedCredentials []string `toml:"credentials"`
	col                *collector.Collector
	d                  director.Director
}

func (s *telnetService) SetDirector(d director.Director) {
	s.d = d
}
func (s *telnetService) SetChannel(c pushers.Channel) {
	s.c = c
}

func (s *telnetService) Handle(conn net.Conn) error {
	// Declare variables used
	banner := []byte("\nUser Access Verification\r\nUsername:")
	timeout := 30 * time.Second
	// Save the current state, username and password
	state := [3]string{"username", "", ""}

	// Send the connection to the collector
	session := s.col.RegisterConnection(conn)
	if aa, ok := conn.(agent.AgentAddresser); ok {
		session.AgentAddr = aa.AgentAddress()
	}

	// When session ends, close the connections and log everything.
	defer s.closeSession(session, conn)

	// Negotiate linemode and echo. Results will be stored in the session.
	s.negotiateTelnet(conn, session)
	s.col.SubmitNegotiation(session.Negotiation)

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
		switch state[0] {
		case "username":
			fallthrough
		case "password":
			session.Credentials.Input = append(session.Credentials.Input, buf[0])
			session.Credentials.InputTimes = append(session.Credentials.InputTimes, time.Since(lastInput).Nanoseconds()/1000000)
		case "interaction":
			session.Interaction.Input = append(session.Interaction.Input, buf[0])
			session.Interaction.InputTimes = append(session.Interaction.InputTimes, time.Since(lastInput).Nanoseconds()/1000000)
		}

		switch buf[0] {
		case 127: // DEL
			fallthrough
		case 8: // Backspace
			// Only deal with Backspace if we're supposed to DO ECHO
			if input.Len() > 0 {
				// Remove the previous character from the buffer
				input.Truncate(input.Len() - 1)
				if state[0] != "password" && session.Negotiation.Valid {
					// Remove the character at the remote host
					conn.Write([]byte("\b \b"))
				}
			}
		case 0: // null
			fallthrough
		case 10: // New Line
			inputString := input.String()
			input.Reset()

			if state[0] == "interaction" {
				// Process the command and add it to the list of commands
				if session.TelnetContainer != nil {
					ccon := *session.TelnetContainer.ContainerConnection

					go func(ccon net.Conn, rc chan byte) {
						reader := bufio.NewReader(ccon)
						for {
							ccon.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
							b, readErr := reader.ReadByte()
							if readErr != nil {
								return
							}
							rc <- b
						}
					}(ccon, session.TelnetContainer.ReplyChannel)

					ccon.Write([]byte(inputString))
					ccon.Write([]byte("\r"))

					count := 0
					var buffer []byte
				replyloop:
					for {
						select {
						case reply := <-session.TelnetContainer.ReplyChannel:
							count++
							// Hack to disable ECHO as telnetd won't accept negotation
							if count > len(inputString) {
								conn.Write([]byte{reply})
								buffer = append(buffer, reply)
							}
						case <-time.After(500 * time.Millisecond):
							break replyloop
						}
					}
					session.Interaction.Commands = append(session.Interaction.Commands, []string{inputString, string(buffer)})
					buffer = make([]byte, 8)
				} else {
					log.Error("Session connection is nil")
				}

			} else {
				state = s.handleNewline(conn, state, inputString, session)
			}
		case 13:
			// Only used in combination with one of the above, ignore.
		default:
			if state[0] != "password" && session.Negotiation.Valid {
				// Echo by default, except if we didn't get a negotiation or when in password mode.
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

func (s *telnetService) handleNewline(conn net.Conn, state [3]string, inputString string, session *u.Session) [3]string {

	if state[0] == "username" {
		// Read all characters in the buffer
		state[1] = inputString
		session.Credentials.Usernames = append(session.Credentials.Usernames, state[1])

		// Switch to password entry
		state[0] = "password"
		conn.Write([]byte("\r\nPassword: "))
	} else {
		// Store all characters in the buffer
		state[2] = inputString

		currentEntry := strings.Join(state[1:], ":")

		session.Credentials.Passwords = append(session.Credentials.Passwords, state[2])
		session.Credentials.Entries = append(session.Credentials.Entries, currentEntry)

		state[1] = ""
		state[2] = ""

		if contains(s.AllowedCredentials, currentEntry) {
			s.col.LogCredentials(session.Credentials)
			state[0] = "interaction"

			telnetContainer := &u.TelnetContainer{
				ContainerConnection: s.dialContainer(conn),
				RemoteConnection:    &conn,
				ReplyChannel:        make(chan byte),
			}
			session.TelnetContainer = telnetContainer
		} else {
			state[0] = "username"
			conn.Write([]byte("\r\nWrong password!\r\n\r\nUsername: "))
		}
	}
	return state
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (s *telnetService) dialContainer(conn net.Conn) *net.Conn {
	cConn, err := s.d.Dial(conn)
	if err != nil {
		log.Error("Error dialing container", err.Error())
	}
	// Handle negotiation
	var conRead [512]byte
	cConn.Read(conRead[0:])
	cConn.Write([]byte{0xff, 0xfb, 0x18, 0xff, 0xfb, 0x20, 0xff, 0xfb,
		0x23, 0xff, 0xfb, 0x27})
	cConn.Read(conRead[0:])
	cConn.Write([]byte{0xff, 0xfa, 0x20, 0x00, 0x33, 0x38, 0x34, 0x30,
		0x30, 0x2c, 0x33, 0x38, 0x34, 0x30, 0x30, 0xff,
		0xf0, 0xff, 0xfa, 0x23, 0x00, 0x6e, 0x79, 0x78,
		0x3a, 0x30, 0xff, 0xf0, 0xff, 0xfa, 0x27, 0x00,
		0x00, 0x44, 0x49, 0x53, 0x50, 0x4c, 0x41, 0x59,
		0x01, 0x6e, 0x79, 0x78, 0x3a, 0x30, 0xff, 0xf0,
		0xff, 0xfa, 0x18, 0x00, 0x58, 0x54, 0x45, 0x52,
		0x4d, 0x2d, 0x32, 0x35, 0x36, 0x43, 0x4f, 0x4c,
		0x4f, 0x52, 0xff, 0xf0})
	cConn.Read(conRead[0:])
	cConn.Write([]byte{0xff, 0xfd, 0x03, u.IAC, u.Wont, u.Echo, 0xff, 0xfb,
		0x1f, 0xff, 0xfa, 0x1f, 0x00, 0xbe, 0x00, 0x30,
		0xff, 0xf0, 0xff, 0xfd, 0x05, 0xff, 0xfb, 0x21})
	cConn.Read(conRead[0:])
	time.Sleep(50 * time.Millisecond)

	// Read username prompt
	cConn.Read(conRead[0:])
	cConn.Write([]byte("admin\r"))
	time.Sleep(50 * time.Millisecond)
	// Read password prompt
	cConn.Read(conRead[0:])
	cConn.Write([]byte("honey\r"))
	time.Sleep(100 * time.Millisecond)
	// Read MOTD
	var prompt [2048]byte
	cConn.Read(prompt[0:])

	log.Debug("Authenticated to container")
	conn.Write(prompt[0:])
	return &cConn
}

func (s *telnetService) negotiateTelnet(conn net.Conn, session *u.Session) (*u.Negotiation, error) {
	negotiation := session.Negotiation
	// Write IAC DO LINE MODE IAC WILL ECH
	conn.Write([]byte{u.IAC, u.Do, u.Linemode, u.IAC, u.Will, u.Echo})

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buffer [1]byte
	_, err := conn.Read(buffer[0:])
	if err != nil {
		negotiation.Valid = false
		return negotiation, err
	}

	negotiation.Bytes = append(negotiation.Bytes, buffer[0])

	// IAC, start of command
	if buffer[0] == u.IAC {
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

func (s *telnetService) closeSession(session *u.Session, conn net.Conn) {
	session.Duration = int(time.Since(session.StartTime).Nanoseconds() / 1000000)
	conn.Close()
	s.col.LogInteraction(session.Interaction)
	s.col.LogSession(session)
}
