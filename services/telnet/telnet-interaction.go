package telnet

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"time"

	u "github.com/honeytrap/honeytrap/services/telnet/util"
	"github.com/op/go-logging"
)

func (s *telnetService) highInteraction(conn net.Conn) (*u.Interaction, error) {
	log = logging.MustGetLogger("services/telnet/interaction")

	interaction := &u.Interaction{}

	telnetContainer := &u.TelnetContainer{
		ContainerConnection: s.dialContainer(conn),
		In:                  make(chan []byte),
	}

	// Process the command and add it to the list of commands
	if telnetContainer != nil {

		interaction.TelnetContainer = telnetContainer
		defer telnetContainer.ContainerConnection.Close()

		// Create a context for closing the following goroutines
		rwctx, rwcancel := context.WithCancel(context.Background())
		defer rwcancel()

		go func() {
			// Proxy all incoming bytes to the container
			for {
				select {
				case <-rwctx.Done():
					return
				case data, ok := <-telnetContainer.In:
					if !ok {
						break
					}
					telnetContainer.ContainerConnection.Write(data)
				}
			}
		}()

		go func() {
			// Read from connection, pass everything on to container
			buf := make([]byte, 32*1024)

			for {
				select {
				case <-rwctx.Done():
					return
				default:
					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					nr, er := conn.Read(buf)
					if er != nil {
						rwcancel()
						log.Errorf("Error reading from connection: %s", er.Error())
						return
					} else if nr == 0 {
						continue
					}
					conn.SetDeadline(time.Time{})

					interaction.Input = append(interaction.Input, buf[:nr]...)
					telnetContainer.In <- buf[:nr]
				}
			}
		}()

		buf := make([]byte, 32*1024)

	readloop:
		for {
			select {
			case <-rwctx.Done():
				break readloop
			default:
				nr, er := telnetContainer.ContainerConnection.Read(buf)
				if er != nil {
					rwcancel()
					break
				} else if nr == 0 {
					continue
				}
				conn.Write(buf[:nr])
			}
		}
	} else {
		log.Error("Session connection is nil")
	}

	interaction.Input = bytes.Replace(interaction.Input, []byte{'\u0000'}, []byte{'\n'}, -1)
	scanner := bufio.NewScanner(bytes.NewReader(interaction.Input))
	for scanner.Scan() {
		interaction.Commands = append(interaction.Commands, scanner.Text())
	}
	if scanner.Err() != nil {
		log.Debugf("Error parsing commands: %s ", scanner.Err().Error())
	}
	return interaction, nil
}

func (s *telnetService) lowInteraction(conn net.Conn, negotiation *u.Negotiation) (*u.Interaction, error) {
	interaction := &u.Interaction{}
	timeout := 30 * time.Second

	// Read one byte at a time
	var buf [1]byte
	var input bytes.Buffer
	lastInput := time.Now()

	for {
		conn.SetDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf[0:])
		if err != nil {
			if err == io.EOF {
				log.Infof("Client closed connection: %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
			} else {
				log.Errorf("Error occurred reading connection: %s => %s:  %s", conn.RemoteAddr().String(), conn.LocalAddr().String(), err.Error())
			}
			return interaction, err
		}
		conn.SetDeadline(time.Time{})

		// Save the received input regardless of content
		interaction.Input = append(interaction.Input, buf[0])
		interaction.InputTimes = append(interaction.InputTimes, time.Since(lastInput).Nanoseconds()/1000000)

		switch buf[0] {
		case 127: // DEL
			fallthrough
		case 8: // Backspace
			// Only deal with Backspace if we're supposed to DO ECHO
			if input.Len() > 0 {
				// Remove the previous character from the buffer
				input.Truncate(input.Len() - 1)
				if negotiation.Valid {
					// Remove the character at the remote host
					conn.Write([]byte("\b \b"))
				}
			}
		case 0: // null
			fallthrough
		case 10: // New Line
			inputString := input.String()
			input.Reset()

			output := s.handleLowInteractionCommand(inputString)
			conn.Write([]byte(output))
			conn.Write([]byte("\r\n# "))
		case 13:
			// Only used in combination with one of the above, ignore.
		default:
			if negotiation.Valid {
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

func (s *telnetService) handleLowInteractionCommand(command string) string {
	switch {
	case command == "whoami":
		return "\r\nadmin\r\n"

	case strings.Contains(command, "/bin/busybox"):
		index := strings.Index(command, "x ")
		appName := command[index+2:]
		return "\r\n" + appName + ": applet not found\r\n"
	default:
		return "\r\n" + command + ": command not found\r\n"
	}
}

func (s *telnetService) dialContainer(conn net.Conn) net.Conn {
	cConn, err := s.d.Dial(conn)
	if err != nil {
		log.Errorf("Error dialing container: %s", err.Error())
	}
	// Handle negotiation
	var conRead [512]byte
	_, err = cConn.Read(conRead[0:])
	if err != nil {
		log.Errorf("Error reading from container: %s", err.Error())
	}
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
	return cConn
}
