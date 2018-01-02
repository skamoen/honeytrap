package telnet

import (
	"bytes"
	"io"
	"net"
	"strings"
	"time"

	u "github.com/honeytrap/honeytrap/services/telnet/util"
	"github.com/op/go-logging"
)

func (s *telnetService) authentication(conn net.Conn, credentials []string, negotiation *u.Negotiation) (*u.Auth, error) {
	log = logging.MustGetLogger("services/telnet/auth")
	timeout := 30 * time.Second
	// Save the current state, username and password
	state := [3]string{"username", "", ""}

	auth := &u.Auth{}

	defer conn.SetDeadline(time.Time{})

	// Read one byte at a time
	var buf [1]byte
	var input bytes.Buffer
	lastInput := time.Now()

	for {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf[0:])
		if err != nil {
			if err == io.EOF {
				log.Infof("Client closed connection: %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
			} else {
				log.Errorf("Error occurred reading connection: %s => %s:  %s", conn.RemoteAddr().String(), conn.LocalAddr().String(), err.Error())
			}
			return auth, err
		}

		// Save the received input regardless of content
		auth.Input = append(auth.Input, buf[0])
		auth.InputTimes = append(auth.InputTimes, time.Since(lastInput).Nanoseconds()/1000000)

		switch buf[0] {
		case 127: // DEL
			fallthrough
		case 8: // Backspace
			// Only deal with Backspace if we're supposed to DO ECHO
			if input.Len() > 0 {
				// Remove the previous character from the buffer
				input.Truncate(input.Len() - 1)
				if state[0] != "password" && negotiation.Valid {
					// Remove the character at the remote host
					conn.Write([]byte("\b \b"))
				}
			}
		case 0: // null
			fallthrough
		case 10: // New Line
			inputString := input.String()
			input.Reset()

			if state[0] == "username" {
				// Read all characters in the buffer
				state[1] = inputString
				auth.Usernames = append(auth.Usernames, state[1])

				// Switch to password entry
				state[0] = "password"
				conn.Write([]byte("\r\nPassword: "))
			} else {
				// Store all characters in the buffer
				state[2] = inputString

				currentEntry := strings.Join(state[1:], ":")

				auth.Passwords = append(auth.Passwords, state[2])
				auth.Entries = append(auth.Entries, currentEntry)

				state[1] = ""
				state[2] = ""

				// Only move to interaction mode if LXC is enabled
				if contains(credentials, currentEntry) {
					// Return with success auth bool
					auth.Success = true
					return auth, nil
				} else {
					state[0] = "username"
					conn.Write([]byte("\r\nWrong password!\r\n\r\nUsername: "))
				}
			}
		case 13:
			// Only used in combination with one of the above, ignore.
		default:
			if state[0] != "password" && negotiation.Valid {
				// Echo by default, except if we didn't get a negotiation or when in password mode.
				if negotiation.ValueEcho {
					_, err := conn.Write(buf[0:n])
					if err != nil {
						log.Errorf("Error writing to connection: %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
					}
				}
			}
			// Store the input
			input.WriteByte(buf[0])
		}
		lastInput = time.Now()
	}
}
