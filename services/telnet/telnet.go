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
	"strconv"
	"strings"
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

	Banners       []string `toml:"banners"`
	ReplaceMounts bool     `toml:"replace-mounts"`
}

func (s *telnetService) SetDirector(d director.Director) {
	s.d = d
}
func (s *telnetService) SetChannel(c pushers.Channel) {
	s.c = c
}

func (s *telnetService) Handle(ctx context.Context, conn net.Conn) error {
	// Send the connection to the collector
	session := s.col.RegisterConnection(conn)

	// When session ends, close the connections and log everything.
	defer s.logSession(session)
	// Close connection first, then log
	defer conn.Close()

	// Negotiate linemode and echo. Results will be stored in the session.
	negotiation, err := s.negotiateTelnet(conn)
	if err != nil {
		return err
	}
	negotiation.Session = session
	session.Negotiation = negotiation

	// Send the banner to the remote host
	//log.Debugf("Sending banner %s => %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	banner := s.selectBanner(conn.LocalAddr())
	session.Banner = banner
	conn.Write([]byte(banner))

	auth, root, err := s.authentication(conn, s.AllowedCredentials, session.Negotiation)
	if err != nil {
		return err
	}
	auth.Session = session
	session.Auth = auth

	if auth.Success {
		if s.d != nil {
			session.Interaction, err = s.highInteraction(conn, root)

		} else {
			session.Interaction, err = s.lowInteraction(conn, session.Negotiation)

		}
		session.Interaction.Session = session
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *telnetService) selectBanner(addr net.Addr) string {
	ip, _, _ := net.SplitHostPort(addr.String())
	a := strings.Split(ip, ".")
	n, err := strconv.ParseInt(a[len(a)-1], 10, 64)
	if err != nil {
		return s.Banners[0]
	}
	l := len(s.Banners)

	if n < 32 {
		return s.Banners[0]
	} else if n < 64 && l >= 2 {
		return s.Banners[1]
	} else if n < 96 && l >= 3 {
		return s.Banners[2]
	} else if n < 128 && l >= 4 {
		return s.Banners[3]
	} else if n < 160 && l >= 5 {
		return s.Banners[4]
	} else if n < 192 && l >= 6 {
		return s.Banners[5]
	} else if n < 224 && l >= 7 {
		return s.Banners[6]
	} else if n < 256 && l >= 8 {
		return s.Banners[7]
	}

	return s.Banners[0]
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
	s.col.LogSession(session)
}
