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
package marija

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"

	"time"

	"github.com/honeytrap/honeytrap/event"
	"github.com/honeytrap/honeytrap/pushers"

	logging "github.com/op/go-logging"
)

var (
	_ = pushers.Register("marija", New)
)

var log = logging.MustGetLogger("channels:marija")

// Backend defines a struct which provides a channel for delivery
// push messages to an elasticsearch api.
type Backend struct {
	Config

	ch chan map[string]interface{}
}

func New(options ...func(pushers.Channel) error) (pushers.Channel, error) {
	ch := make(chan map[string]interface{}, 100)

	c := Backend{
		ch: ch,
	}

	for _, optionFn := range options {
		optionFn(&c)
	}

	go c.run()

	return &c, nil
}

func Insecure(config *tls.Config) *tls.Config {
	config.InsecureSkipVerify = true
	return config
}

func (hc Backend) run() {
	log.Debug("Marija channel started...")
	defer log.Debug("Marija channel stopped...")

	tlsClientConfig := &tls.Config{}

	if hc.Insecure {
		tlsClientConfig = Insecure(tlsClientConfig)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	for {
		select {
		case doc := <-hc.ch:
			buffer := &bytes.Buffer{}

			err := json.NewEncoder(buffer).Encode(doc)

			req, err := http.NewRequest(http.MethodPost, hc.URL, buffer)
			if err != nil {
				log.Errorf("Could create new request: %s", err.Error())
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				log.Errorf("Could not submit event to Marija: %s", err.Error())
				continue
			}

			if resp.StatusCode != http.StatusOK {
				log.Errorf("Could not submit event to Marija: %d", resp.StatusCode)
				continue
			}

		case <-time.After(time.Second * 10):
		}
	}
}

func filter(key string) bool {
	validKeys := []string{
		"source-ip",
		"destination-ip",
		"destination-port",
	}

	for _, vk := range validKeys {
		if vk == key {
			return false
		}
	}

	return true
}

// Send delivers the giving push messages into the internal elastic search endpoint.
func (hc Backend) Send(message event.Event) {
	mp := make(map[string]interface{})

	message.Range(func(key, value interface{}) bool {
		if filter(key.(string)) {
			return true
		}

		if keyName, ok := key.(string); ok {
			mp[keyName] = value
		}

		return true
	})

	select {
	case hc.ch <- mp:
	default:
		log.Errorf("Could not send more messages, channel full")
	}
}
