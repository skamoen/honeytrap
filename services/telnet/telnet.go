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

	// Lazy import for util structs

	"context"
	"net"
	"time"

	"github.com/op/go-logging"

	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers"
	"github.com/honeytrap/honeytrap/services"

	"github.com/honeytrap/honeytrap/services/telnet/collector"
	u "github.com/honeytrap/honeytrap/services/telnet/util"
)

var log = logging.MustGetLogger("services/telnet")

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

func (s *telnetService) Handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	// Declare variables used
	banner := []byte("\nUser Access Verification\r\nUsername:")

	// Send the connection to the collector
	session := s.col.RegisterConnection(conn)

	// When session ends, close the connections and log everything.
	defer s.logSession(session)

	// Negotiate linemode and echo. Results will be stored in the session.
	negotiation, err := s.negotiateTelnet(conn)
	if err != nil {
		return err
	}
	negotiation.Session = session
	session.Negotiation = negotiation
	s.col.LogNegotiation(session.Negotiation)

	// Send the banner to the remote host
	log.Debugf("Sending banner %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	conn.Write(banner)

	auth, err := s.authentication(conn, s.AllowedCredentials, session.Negotiation)
	if err != nil {
		return err
	}
	auth.Session = session
	session.Auth = auth
	s.col.LogCredentials(session.Auth)

	if auth.Success {
		if s.d != nil {
			interaction, err := s.highInteraction(conn)
			interaction.Session = session
			session.Interaction = interaction
			if err != nil {
				return err
			}
		} else {
			interaction, err := s.lowInteraction(conn, session.Negotiation)
			interaction.Session = session
			session.Interaction = interaction
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (s *telnetService) logSession(session *u.Session) {
	session.Duration = int(time.Since(session.StartTime).Nanoseconds() / 1000000)
	s.col.LogInteraction(session.Interaction)
	s.col.LogSession(session)
}
