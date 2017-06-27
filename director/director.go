package director

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/honeytrap/honeytrap/config"
	"github.com/honeytrap/honeytrap/pushers"

	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("honeytrap:director")

//=======================================================================================================

// DirectorGenerator defines a function type which returns a Channel created
// from a primitive.
type DirectorGenerator func(*config.Config, toml.MetaData, toml.Primitive, pushers.Channel) (Director, error)

// TODO(alex): Decide if we need a mutex to secure things concurrently.
// We assume it will never be read/written to concurrently.
var backends = struct {
	b map[string]DirectorGenerator
}{
	b: make(map[string]DirectorGenerator),
}

// RegisterDirector adds the giving generator to the global generator lists.
func RegisterDirector(name string, generator DirectorGenerator) DirectorGenerator {
	backends.b[name] = generator
	return generator
}

// NewDirector returns a new Director of the giving name with the provided toml.Primitive.
func NewDirector(con *config.Config, meta toml.MetaData, primi toml.Primitive, ch pushers.Channel) (Director, error) {
	log.Debug("Initializing director : %#q", con.Director)

	maker, ok := backends.b[con.Director]
	if !ok {
		return nil, fmt.Errorf("Director with name %q not found", con.Director)
	}

	return maker(con, meta, primi, ch)
}

//=======================================================================================================

// Director defines an interface which exposes an interface to allow structures that
// implement this interface allow us to control containers which they provide.
type Director interface {
	NewContainer(string) (Container, error)
	GetContainer(net.Conn) (Container, error)
	ListContainers() []ContainerDetail
}

// Container defines a type which exposes methods for connecting to a container.
type Container interface {
	Name() string
	Detail() ContainerDetail
	Dial(context.Context, port string) (net.Conn, error)
}

// ContainerDetail defines a struct which is used to detail specific container meta-data.
type ContainerDetail struct {
	Name          string                 `json:"name"`
	ContainerAddr string                 `json:"container_addr"`
	Meta          map[string]interface{} `json:"meta"`
}

// ClientDetail defines which contains details related to clients connected
// to the containers generated from the directors.
type ClientDetail struct {
	RemoteAddr string          `json:"remote_addr"`
	LocalAddr  string          `json:"local_addr"`
	Container  ContainerDetail `json:"container"`
}

// ContainerConnections defines a struct which provides a central management
// structure for all connected containers and their connections.
type ContainerConnections struct {
	connections   map[string][]net.Conn
	clients       map[string]ContainerDetail
	newClient     chan newClientConnection
	rmClient      chan string
	rmResponse    chan error
	rmClientConns chan string
	clientList    chan chan []ClientDetail
}

// newClientConnection defines the object used to delivery a new connection
// request to the ContainerConnections for recording.
type newClientConnection struct {
	Conn      net.Conn
	Container ContainerDetail
}

// NewContainerConnections returns a new instance of a ContainerConnection
func NewContainerConnections() *ContainerConnections {
	cc := &ContainerConnections{
		connections:   make(map[string][]net.Conn),
		clients:       make(map[string]ContainerDetail),
		newClient:     make(chan newClientConnection),
		rmResponse:    make(chan error),
		rmClient:      make(chan string),
		rmClientConns: make(chan string),
		clientList:    make(chan chan []ClientDetail),
	}

	go cc.manage()

	return cc
}

// ListClients returns the list of all connected Clients.
func (cn *ContainerConnections) ListClients() []ClientDetail {
	reqs := make(chan []ClientDetail)

	cn.clientList <- reqs

	return <-reqs
}

// RemoveClientWithConns removes the connection container if available.
func (cn *ContainerConnections) RemoveClientWithConns(client string) error {
	cn.rmClientConns <- client
	return <-cn.rmResponse
}

// RemoveClient removes the connection container if available.
func (cn *ContainerConnections) RemoveClient(client string) error {
	cn.rmClient <- client
	return <-cn.rmResponse
}

// AddClient adds the giving new client net.Conn and container details into
// the registry.
func (cn *ContainerConnections) AddClient(conn net.Conn, detail ContainerDetail) {
	cn.newClient <- newClientConnection{
		Conn:      conn,
		Container: detail,
	}
}

// manage contains the logic needed to efficiently and concurrently manage
// all internal operations and request for the ContainerConnections.
func (cn *ContainerConnections) manage() {
	{
	nloop:
		for {
			select {
			case newClient, ok := <-cn.newClient:
				if !ok {
					return
				}

				_, clientFound := cn.clients[newClient.Container.Name]
				if !clientFound {
					cn.connections[newClient.Container.Name] = []net.Conn{newClient.Conn}
					cn.clients[newClient.Container.Name] = newClient.Container

					continue nloop
				}

				connections, connFound := cn.connections[newClient.Container.Name]
				if !connFound {
					continue nloop
				}

				connections = append(connections, newClient.Conn)
				cn.connections[newClient.Container.Name] = connections

			case reqChan, ok := <-cn.clientList:
				if !ok {
					return
				}

				var clients []ClientDetail

				for _, client := range cn.clients {
					for _, conn := range cn.connections[client.Name] {
						clients = append(clients, ClientDetail{
							Container:  client,
							RemoteAddr: conn.RemoteAddr().String(),
							LocalAddr:  conn.LocalAddr().String(),
						})
					}
				}

				reqChan <- clients

			case clientID, ok := <-cn.rmClient:
				if !ok {
					return
				}

				_, clientFound := cn.clients[clientID]
				if !clientFound {
					cn.rmResponse <- fmt.Errorf("Container with ID: %q does not exists", clientID)
					continue nloop
				}

				delete(cn.clients, clientID)

				_, connFound := cn.connections[clientID]
				if connFound {
					delete(cn.connections, clientID)
				}

				cn.rmResponse <- nil

			case clientID, ok := <-cn.rmClientConns:
				if !ok {
					return
				}

				_, clientFound := cn.clients[clientID]
				if !clientFound {
					cn.rmResponse <- fmt.Errorf("Container with ID: %q does not exists", clientID)
					continue nloop
				}

				delete(cn.clients, clientID)

				connections, connFound := cn.connections[clientID]
				if connFound {
					delete(cn.connections, clientID)
				}

				for _, conn := range connections {
					conn.Close()
				}

				cn.rmResponse <- nil
			}
		}
	}
}

// GetHostAddr takes the giving address string and if it has no ip or use the
// zeroth ip format, then modifies the ip with the current systems ip.
func GetHostAddr(addr string) string {
	if addr == "" {
		if real, err := GetMainIP(); err == nil {
			return real + ":0"
		}
	}

	ip, port, err := net.SplitHostPort(addr)
	if err == nil && ip == "" || ip == "0.0.0.0" {
		if realIP, err := GetMainIP(); err == nil {
			return net.JoinHostPort(realIP, port)
		}
	}

	return addr
}

// getMainIP returns the giving system IP by attempting to connect to a imaginary
// ip and returns the giving system ip.
func getMainIP() (string, error) {
	udp, err := net.DialTimeout("udp", "8.8.8.8:80", 1*time.Millisecond)
	if udp == nil {
		return "", err
	}

	defer udp.Close()

	localAddr := udp.LocalAddr().String()
	ip, _, _ := net.SplitHostPort(localAddr)

	return ip, nil
}
