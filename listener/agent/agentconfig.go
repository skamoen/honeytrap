package agent

var (
	agents = map[string]func(...func(Agent) error) (Agent, error){}
)

type Agent struct {
}

func Register(key string, fn func(...func(Agent) error) (Agent, error)) func(...func(Agent) error) (Agent, error) {
	agents[key] = fn
	return fn
}

func Get(key string) (func(...func(Agent) error) (Agent, error), bool) {
	if fn, ok := agents[key]; ok {
		return fn, true
	}

	return nil, false
}
