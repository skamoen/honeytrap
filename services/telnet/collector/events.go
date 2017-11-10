package collector

import (
	"github.com/honeytrap/honeytrap/pushers"
)

func (col *Collector) LogMetrics(c pushers.Channel) {
	// // Convert raw bytes to "readable" int values
	// bytes := make([]int, len(s.Metrics.Input))
	// for i, b := range s.Metrics.Input {
	// 	bytes[i] = int(b)
	// }

	// metricsMap := map[string]interface{}{
	// 	"raw":              s.Raw,
	// 	"session_start":    s.StartTime,
	// 	"session_duration": time.Since(s.StartTime) / 1000000,
	// 	"input_bytes":      bytes,
	// 	"input_times":      s.Metrics.InputTimes,
	// 	"usernames":        s.Metrics.Usernames,
	// 	"passwords":        s.Metrics.Passwords,
	// 	"entries":          s.Metrics.Entries,
	// }

	// c.Send(event.New(
	// 	event.Service("telnet"),
	// 	event.Category("session"),
	// 	event.Type("metrics"),
	// 	event.DestinationAddr(s.LocalAddr),
	// 	event.SourceAddr(s.RemoteAddr),
	// 	event.CopyFrom(metricsMap),
	// ))
}

func (col *Collector) LogNegotiation(c pushers.Channel) {
	// // Convert raw bytes to "readable" int values
	// bytes := make([]int, len(s.Negotiation.Bytes))
	// for i, b := range s.Negotiation.Bytes {
	// 	bytes[i] = int(b)
	// }
	// c.Send(event.New(
	// 	event.Service("telnet"),
	// 	event.Category("session"),
	// 	event.Type("negotiation"),
	// 	event.DestinationAddr(s.LocalAddr),
	// 	event.SourceAddr(s.RemoteAddr),
	// 	event.Custom("bytes", bytes),
	// 	event.Custom("echo", s.Negotiation.ValueEcho),
	// 	event.Custom("linemode", s.Negotiation.ValueLinemode),
	// 	event.Custom("seen", s.Negotiation.seenBefore),
	// ))
}
