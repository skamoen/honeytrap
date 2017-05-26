package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dimfeld/httptreemux"
	assetfs "github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/websocket"
	"github.com/honeytrap/honeytrap/config"
	"github.com/honeytrap/honeytrap/director"
	"github.com/honeytrap/honeytrap/pushers/message"
)

//=============================================================================================================

// Contains the different buckets used
var (
	eventsBucket  = []byte(message.EventSensor)
	sessionBucket = []byte(message.SessionSensor)

	pingEventsBucket = []byte(message.PingEvent)
)

//=============================================================================================================

// HoneycastOption defines a function which is used to enchance/add configurational
// options for use with the honeycast API.
type HoneycastOption func(*Honeycast)

// AcceptAllOrigins defines a function to use to validate origin request.
func AcceptAllOrigins(r *http.Request) bool { return true }

// HoneycastAssets sets the assets http.Handler for use with a Honeycast instance.
func HoneycastAssets(assets *assetfs.AssetFS) HoneycastOption {
	return func(hc *Honeycast) {
		hc.assets = http.FileServer(assets)
	}
}

//=============================================================================================================

// Honeycast defines a struct which exposes methods to handle api related service
// responses.
type Honeycast struct {
	*httptreemux.TreeMux
	bolted   *Bolted
	socket   *Socketcast
	assets   http.Handler
	config   *config.Config
	director director.Director
	manager  *director.ContainerConnections
}

// NewHoneycast returns a new instance of a Honeycast struct.
func NewHoneycast(config *config.Config, manager *director.ContainerConnections, dir director.Director, options ...HoneycastOption) *Honeycast {

	// Create the database we desire.
	// TODO: Should we really panic here, it makes sense to do that, since it's the server
	// right?
	bolted, err := NewBolted(fmt.Sprintf("%s-bolted", config.Token), message.ContainersSensor, message.ConnectionSensor, message.ServiceSensor, message.SessionSensor, message.PingSensor, message.DataSensor, message.ErrorsSensor, message.EventSensor)
	if err != nil {
		log.Errorf("Failed to created BoltDB session: %+q", err)
		panic(err)
	}

	var hc Honeycast
	hc.config = config
	hc.bolted = bolted
	hc.director = dir
	hc.manager = manager
	hc.TreeMux = httptreemux.New()
	hc.socket = NewSocketcast(config, bolted, AcceptAllOrigins)

	// Register endpoints for events.
	hc.TreeMux.Handle("GET", "/", hc.Index)
	hc.TreeMux.Handle("GET", "/events", hc.Events)
	hc.TreeMux.Handle("GET", "/sessions", hc.Sessions)
	hc.TreeMux.Handle("GET", "/ws", hc.socket.ServeHandle)

	// Register endpoints for metrics details
	hc.TreeMux.Handle("GET", "/metrics/attackers", hc.Attackers)
	hc.TreeMux.Handle("GET", "/metrics/containers", hc.Containers)

	// Register endpoints for container interaction details
	hc.TreeMux.Handle("DELETE", "/containers/clients/:container_id", hc.ContainerClientDelete)
	hc.TreeMux.Handle("DELETE", "/containers/connections/:container_id", hc.ContainerConnectionsDelete)

	return &hc
}

// ContainerClientDelete services the request to delete a giving containers client detail without
// affecting the existing connections.
func (h *Honeycast) ContainerClientDelete(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if err := h.manager.RemoveClient(params["container_id"]); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ContainerConnectionsDelete services the request to delete a giving containers client detail and
// related existing connections.
func (h *Honeycast) ContainerConnectionsDelete(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if err := h.manager.RemoveClientWithConns(params["container_id"]); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AttackerResponse defines the response delivered for requesting list of all
// current container users.
type AttackerResponse struct {
	Total     int                     `json:"total"`
	Attackers []director.ClientDetail `json:"attackers"`
}

// Attackers delivers metrics from the underlying API about specific users
// of the current running dataset.
func (h *Honeycast) Attackers(w http.ResponseWriter, r *http.Request, params map[string]string) {
	users := h.manager.ListClients()

	response := AttackerResponse{
		Total:     len(users),
		Attackers: users,
	}

	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")

	if err := encoder.Encode(response); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// ContainerResponse defines the response delivered for requesting list of all containers
// lunched.
type ContainerResponse struct {
	Total      int                        `json:"total"`
	Containers []director.ContainerDetail `json:"containers"`
}

// Containers delivers metrics from the underlying API about specific data related to containers
// started, stopped and running.
func (h *Honeycast) Containers(w http.ResponseWriter, r *http.Request, params map[string]string) {
	containers := h.director.ListContainers()

	response := ContainerResponse{
		Total:      len(containers),
		Containers: containers,
	}

	w.WriteHeader(http.StatusOK)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")

	if err := encoder.Encode(response); err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// Send delivers the underline provided messages and stores them into the underline
// Honeycast database for retrieval through the API.
func (h *Honeycast) Send(msgs []message.PushMessage) {
	var containers, connections, data, services, pings, serrors, sessions, events []message.Event

	// Seperate out the event types appropriately.
	for _, msg := range msgs {
		if !msg.Event {
			continue
		}

		event, ok := msg.Data.(message.Event)
		if !ok {
			continue
		}

		events = append(events, event)

		switch event.Sensor {
		case message.SessionSensor:
			sessions = append(sessions, event)
		case message.PingSensor:
			pings = append(pings, event)
		case message.DataSensor:
			data = append(data, event)
		case message.ServiceSensor:
			services = append(services, event)
		case message.ContainersSensor:
			containers = append(containers, event)
		case message.ConnectionSensor:
			connections = append(connections, event)
		case message.ConnectionErrorSensor, message.DataErrorSensor:
			serrors = append(serrors, event)
		}
	}

	// Batch deliver both sessions and events data to all connected
	h.socket.events <- events
	h.socket.sessions <- sessions

	//  Batch save all events into individual buckets.
	if terr := h.bolted.Save([]byte(message.SessionSensor), sessions...); terr != nil {
		log.Errorf("Honeycast API : Failed to save session events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.ErrorsSensor), serrors...); terr != nil {
		log.Errorf("Honeycast API : Failed to save errors events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.ConnectionSensor), connections...); terr != nil {
		log.Errorf("Honeycast API : Failed to save connections events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.ServiceSensor), services...); terr != nil {
		log.Errorf("Honeycast API : Failed to save service events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.ContainersSensor), containers...); terr != nil {
		log.Errorf("Honeycast API : Failed to save data events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.DataSensor), data...); terr != nil {
		log.Errorf("Honeycast API : Failed to save data events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.PingSensor), pings...); terr != nil {
		log.Errorf("Honeycast API : Failed to save ping events to db: %+q", terr)
	}

	if terr := h.bolted.Save([]byte(message.EventSensor), events...); terr != nil {
		log.Errorf("Honeycast API : Failed to save events to db: %+q", terr)
	}
}

// Sessions handles response for all `/sessions` target endpoint and returns all giving push
// messages returns the slice of data.
func (h *Honeycast) Sessions(w http.ResponseWriter, r *http.Request, params map[string]string) {
	total, err := h.bolted.GetSize(sessionBucket)
	if err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var req EventRequest

	if terr := json.NewDecoder(r.Body).Decode(&req); terr != nil {
		log.Error("Honeycast API : Invalid Request Object data: %+q", terr)
		http.Error(w, "Invalid Request Object data: "+terr.Error(), http.StatusInternalServerError)
		return
	}

	var res EventResponse
	res.Total = total
	res.Page = req.Page
	res.ResponsePerPage = req.ResponsePerPage

	if req.ResponsePerPage <= 0 || req.Page <= 0 {

		var terr error
		res.Events, terr = h.bolted.Get(sessionBucket, -1, -1)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", err)
			http.Error(w, "Invalid 'From' parameter: "+terr.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		length := req.ResponsePerPage * req.Page
		index := (length / 2)

		if req.Page > 1 {
			index++
		}

		var terr error
		var events, filteredEvents []message.Event

		events, terr = h.bolted.Get(eventsBucket, index, length)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", err)
			http.Error(w, "Invalid 'From' parameter: "+terr.Error(), http.StatusInternalServerError)
			return
		}

		{
			doTypeMatch := len(req.TypeFilters) != 0
			doSensorMatch := len(req.SensorFilters) != 0

			if doTypeMatch || doSensorMatch {
				for _, event := range events {

					var typeMatched bool
					var sensorMatched bool

					{
					typeFilterLoop:
						for _, tp := range req.TypeFilters {
							// If we match atleast one type then allow event event.
							if string(event.Type) == tp {
								typeMatched = true
								break typeFilterLoop
							}
						}

						// If there are type filters and event does not match, skip.
						if doTypeMatch && !typeMatched {
							continue
						}
					}

					{
					sensorFilterLoop:
						for _, tp := range req.SensorFilters {
							// If we match atleast one type then allow event event.
							if strings.ToLower(event.Sensor) == strings.ToLower(tp) {
								sensorMatched = true
								break sensorFilterLoop
							}
						}

						// If there are sensor filters and event does not match, skip.
						if doSensorMatch && !sensorMatched {
							continue
						}

					}

					filteredEvents = append(filteredEvents, event)
				}

				res.Events = filteredEvents
			} else {
				res.Events = events
			}
		}
	}

	var bu bytes.Buffer
	if jserr := json.NewEncoder(&bu).Encode(res); jserr != nil {
		log.Error("Honeycast API : Invalid 'From' Param: %+q", jserr)
		http.Error(w, "Invalid 'From' parameter: "+jserr.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(bu.Bytes())
}

// Events handles response for all `/events` target endpoint and returns all giving events
// and expects a giving filter paramter which will be used to filter out the needed events.
func (h *Honeycast) Events(w http.ResponseWriter, r *http.Request, params map[string]string) {
	total, err := h.bolted.GetSize(eventsBucket)
	if err != nil {
		log.Error("Honeycast API : Operation Failed : %+q", err)
		http.Error(w, "Operation Failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var req EventRequest

	if terr := json.NewDecoder(r.Body).Decode(&req); terr != nil {
		log.Error("Honeycast API : Invalid Request Object data: %+q", terr)
		http.Error(w, "Invalid Request Object data: "+terr.Error(), http.StatusInternalServerError)
		return
	}

	var res EventResponse
	res.Total = total
	res.Page = req.Page
	res.ResponsePerPage = req.ResponsePerPage

	var terr error

	if req.ResponsePerPage <= 0 || req.Page <= 0 {

		res.Events, terr = h.bolted.Get(eventsBucket, -1, -1)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", err)
			http.Error(w, "Invalid 'From' parameter: "+terr.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		length := req.ResponsePerPage * req.Page
		index := (length / 2)

		if req.Page > 1 {
			index++
		}

		var terr error
		var events, filteredEvents []message.Event

		events, terr = h.bolted.Get(eventsBucket, index, length)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response received : %+q", err)
			http.Error(w, "Invalid 'From' parameter: "+terr.Error(), http.StatusInternalServerError)
			return
		}

		{
			doTypeMatch := len(req.TypeFilters) != 0
			doSensorMatch := len(req.SensorFilters) != 0

			if doTypeMatch || doSensorMatch {
				for _, event := range events {

					var typeMatched bool
					var sensorMatched bool

					{
					typeFilterLoop:
						for _, tp := range req.TypeFilters {
							// If we match atleast one type then allow event event.
							if string(event.Type) == tp {
								typeMatched = true
								break typeFilterLoop
							}
						}

						// If there are type filters and event does not match, skip.
						if doTypeMatch && !typeMatched {
							continue
						}
					}

					{
					sensorFilterLoop:
						for _, tp := range req.SensorFilters {

							sensorRegExp, err := regexp.Compile(tp)
							if err != nil {
								log.Errorf("Honeycast API : Failed to creat match for %q : %+q", tp, err)
								continue sensorFilterLoop
							}

							// If we match atleast one type then allow event event.
							if sensorRegExp.MatchString(event.Sensor) {
								sensorMatched = true
								break sensorFilterLoop
							}
						}

						// If there are sensor filters and event does not match, skip.
						if doSensorMatch && !sensorMatched {
							continue
						}

					}

					filteredEvents = append(filteredEvents, event)
				}

				res.Events = filteredEvents
			} else {
				res.Events = events
			}
		}

	}

	var bu bytes.Buffer
	if jserr := json.NewEncoder(&bu).Encode(res); jserr != nil {
		log.Error("Honeycast API : Invalid 'From' Param: %+q", jserr)
		http.Error(w, "Invalid 'From' parameter: "+jserr.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(bu.Bytes())
}

// Index handles the servicing of index based requests for the giving service.
func (h *Honeycast) Index(w http.ResponseWriter, r *http.Request, params map[string]string) {
	if h.assets != nil {
		h.assets.ServeHTTP(w, r)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

//=================================================================================

const (
	maxBufferSize       = 1024 * 1024
	maxPingPongInterval = 5 * time.Second
	maxPingPongWait     = (maxPingPongInterval * 9) / 10
)

type targetMessage struct {
	client  *websocket.Conn
	message []byte
	mtype   int
}

// Socketcast defines structure which exposes specific interface for interacting with a
// websocket structure.
type Socketcast struct {
	uprader      websocket.Upgrader
	transport    *SocketTransport
	clients      map[*websocket.Conn]bool
	newClients   chan *websocket.Conn
	closeClients chan *websocket.Conn
	events       chan []message.Event
	sessions     chan []message.Event
	close        chan struct{}
	data         chan targetMessage
	wg           sync.WaitGroup
	closed       bool
}

// NewSocketcast returns a new instance of a Socketcast.
func NewSocketcast(config *config.Config, db *Bolted, origins func(*http.Request) bool) *Socketcast {
	var socket Socketcast

	socket.uprader = websocket.Upgrader{
		ReadBufferSize:  maxBufferSize,
		WriteBufferSize: maxBufferSize,
		CheckOrigin:     origins,
	}

	socket.close = make(chan struct{}, 0)
	socket.data = make(chan targetMessage, 0)
	socket.events = make(chan []message.Event, 0)
	socket.clients = make(map[*websocket.Conn]bool)
	socket.sessions = make(chan []message.Event, 0)
	socket.newClients = make(chan *websocket.Conn, 0)
	socket.closeClients = make(chan *websocket.Conn, 0)
	socket.transport = SocketTransportWithDB(config, db)

	// spin up the socket internal processes.
	go socket.manage()

	return &socket
}

// ServeHandle defines a method which implements the httptreemux.Handle to allow us easily,
// use the socket as a server to a giving httptreemux.Tree router.
func (socket *Socketcast) ServeHandle(w http.ResponseWriter, r *http.Request, _ map[string]string) {
	socket.ServeHTTP(w, r)
}

// Close ends the internal routine of the Socket server.
func (socket *Socketcast) Close() error {
	if socket.closed {
		return errors.New("Already Closed")
	}

	close(socket.close)
	socket.closed = true

	socket.wg.Wait()

	return nil
}

// manage runs the loop to manage the connections and message delivery processes of the
// Socketcast instance.
func (socket *Socketcast) manage() {
	socket.wg.Add(1)
	defer socket.wg.Done()

	ticker := time.NewTicker(maxPingPongInterval)

	{
	mloop:
		for {
			select {
			case <-ticker.C:

				for client := range socket.clients {
					client.WriteMessage(websocket.PingMessage, nil)
				}

			case newConn, ok := <-socket.newClients:
				if !ok {
					ticker.Stop()
					break mloop
				}

				socket.clients[newConn] = true

			case message, ok := <-socket.data:
				if !ok {
					ticker.Stop()
					break mloop
				}

				if err := socket.transport.HandleMessage(message.message, message.client); err != nil {
					log.Error("Honeycast API : Failed to process message : %+q : %+q", message, err)
				}

			case closeConn, ok := <-socket.closeClients:
				if !ok {
					ticker.Stop()
					break mloop
				}

				delete(socket.clients, closeConn)

				// Close the connection as well.
				closeConn.WriteMessage(websocket.CloseMessage, nil)
				closeConn.Close()

			case newEvents, ok := <-socket.events:
				if !ok {
					ticker.Stop()
					break mloop
				}

				for client := range socket.clients {
					if err := socket.transport.DeliverNewEvents(newEvents, client); err != nil {
						log.Error("Honeycast API : Failed to deliver events : %+q : %+q", client.RemoteAddr(), err)
					}
				}

			case newEvents, ok := <-socket.sessions:
				if !ok {
					ticker.Stop()
					break mloop
				}

				for client := range socket.clients {
					if err := socket.transport.DeliverNewSessions(newEvents, client); err != nil {
						log.Error("Honeycast API : Failed to deliver events : %+q : %+q", client.RemoteAddr(), err)
					}
				}
			}
		}
	}
}

// ServeHTTP serves and transforms incoming request into websocket connections.
func (socket *Socketcast) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := socket.uprader.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Honeycast API : Failed to uprade request : %+q", err)
		http.Error(w, "Failed to upgrade request", http.StatusInternalServerError)
		return
	}

	conn.SetPongHandler(func(appData string) error {
		conn.SetReadDeadline(time.Now().Add(maxPingPongWait))
		return nil
	})

	// Register new connection into our client map and routine.
	socket.newClients <- conn

	{
		for {
			messageType, message, err := conn.ReadMessage()
			if err != nil {
				// Error possibly occured, so we need to stop here.
				log.Error("Honeycast API : Connection read failed abruptly : %+q", err)
				socket.closeClients <- conn
				return
			}

			conn.SetReadDeadline(time.Time{})

			switch messageType {
			case websocket.CloseMessage:
				socket.closeClients <- conn
				return
			}

			socket.data <- targetMessage{
				client:  conn,
				message: message,
				mtype:   messageType,
			}
		}
	}

}

//=============================================================================================

// SocketTransport defines a struct which implements a message consumption and
// response transport for use over a websocket connection.
type SocketTransport struct {
	bolted *Bolted
	config *config.Config
}

// SocketTransportWithDB returns a new instance of a SocketTransport using the provided
// Bolted instance.
func SocketTransportWithDB(config *config.Config, bolt *Bolted) *SocketTransport {
	var socket SocketTransport
	socket.config = config
	socket.bolted = bolt
	return &socket
}

// NewSocketTransport returns a new instance of a SocketTransport.
func NewSocketTransport(config *config.Config) (*SocketTransport, error) {
	var socket SocketTransport
	socket.config = config

	// Create the database we desire.
	bolted, err := NewBolted(fmt.Sprintf("%s-bolted", config.Token), string(sessionBucket), string(eventsBucket))
	if err != nil {
		log.Errorf("Failed to created BoltDB session: %+q", err)
		return nil, err
	}

	socket.bolted = bolted

	return &socket, nil
}

// HandleMessage defines a central method which provides the entry point which is used
// to respond to new messages.
func (so *SocketTransport) HandleMessage(message []byte, conn *websocket.Conn) error {
	var newMessage Message

	if err := json.NewDecoder(bytes.NewBuffer(message)).Decode(&newMessage); err != nil {
		log.Errorf("Honeycast API : Failed to decode message : %+q", err)
		return err
	}

	// We initially will only handle just two requests of getter types.
	// TODO: Handle NewSessions and NewEvents somewhere else.
	switch newMessage.Type {
	case FetchEvents:
		var message Message
		message.Type = FetchEventsReply

		var terr error
		message.Payload, terr = so.bolted.Get(eventsBucket, -1, -1)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response with Sessions Retrieval : %+q", terr)
			return so.DeliverMessage(Message{
				Type:    ErrorResponse,
				Payload: terr.Error(),
			}, conn)
		}

		return so.DeliverMessage(message, conn)

	case FetchSessions:
		var message Message
		message.Type = FetchSessionsReply

		var terr error
		message.Payload, terr = so.bolted.Get(sessionBucket, -1, -1)
		if terr != nil {
			log.Error("Honeycast API : Invalid Response with Sessions Retrieval : %+q", terr)
			return so.DeliverMessage(Message{
				Type:    ErrorResponse,
				Payload: terr.Error(),
			}, conn)
		}

		return so.DeliverMessage(message, conn)

	default:
		return so.DeliverMessage(Message{
			Type:    ErrorResponse,
			Payload: "Unknown Request Type",
		}, conn)
	}
}

// DeliverNewSessions delivers new incoming requests to the underline socket transport.
func (so *SocketTransport) DeliverNewSessions(events []message.Event, conn *websocket.Conn) error {
	if events == nil {
		return nil
	}

	return so.DeliverMessage(Message{
		Type:    NewSessions,
		Payload: events,
	}, conn)
}

// DeliverNewEvents delivers new incoming requests to the underline socket transport.
func (so *SocketTransport) DeliverNewEvents(events []message.Event, conn *websocket.Conn) error {
	if events == nil {
		return nil
	}

	return so.DeliverMessage(Message{
		Type:    NewEvents,
		Payload: events,
	}, conn)
}

// DeliverMessage defines a method which handles the delivery of a message to a giving
// websocket.Conn.
func (so *SocketTransport) DeliverMessage(message Message, conn *websocket.Conn) error {
	var bu bytes.Buffer

	if err := json.NewEncoder(&bu).Encode(message); err != nil {
		log.Errorf("Honeycast API : Failed to decode message : %+q", err)
		return err
	}

	return conn.WriteMessage(websocket.BinaryMessage, bu.Bytes())
}

//=====================================================================================================

// Contains values for use.
const (
	ResponsePerPageHeader = "response_per_page"
	PageHeader            = "page"
)

// EventResponse defines a struct which is sent a request type used to respond to
// given requests.
type EventResponse struct {
	ResponsePerPage int             `json:"responser_per_page"`
	Page            int             `json:"page"`
	Total           int             `json:"total"`
	Events          []message.Event `json:"events"`
}

// EventRequest defines a struct which receives a request type used to retrieve
// given requests type.
type EventRequest struct {
	ResponsePerPage int      `json:"responser_per_page"`
	Page            int      `json:"page"`
	TypeFilters     []string `json:"types"`
	SensorFilters   []string `json:"sensors"`
}