package telnet

import (
	"net"
	"strings"
)

type Interaction struct {
	commands []string
}

func (s *telnetService) lowInteraction(conn net.Conn, inputString string) {
	switch {
	case inputString == "whoami":
		conn.Write([]byte("\r\nadmin\r\n"))

	case strings.Contains(inputString, "/bin/busybox"):
		index := strings.Index(inputString, "x ")
		appName := inputString[index+2:]
		conn.Write([]byte("\r\n" + appName + ": applet not found\r\n"))

	default:
		conn.Write([]byte("\r\n" + inputString + ": command not found\r\n"))
	}

	conn.Write([]byte("\r\n# "))

	return
}
