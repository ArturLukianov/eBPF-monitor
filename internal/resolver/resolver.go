// This code resolves information about containers.
// Currently, only Docker is supported.

package resolver

import (
	"sync"

	// It is possible I need to use moby instead - https://github.com/moby/moby/discussions/50472
	"github.com/docker/docker/client"
)

type ContainerInfo struct {
	ID             string
	Name           string
	Image          string
	ComposeProject string
}

type Resolver struct {
	mu     sync.RWMutex
	cache  map[uint64]*ContainerInfo // cgroup_id -> ContainerInfo
	docker *client.Client
}

func New() (*Resolver, error) {
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}

	r := &Resolver{
		cache:  make(map[uint64]*ContainerInfo),
		docker: client,
	}
	return r, nil
}
