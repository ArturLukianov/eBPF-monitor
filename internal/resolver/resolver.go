// This code resolves information about containers.
// Currently, only Docker is supported.

package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	// It is possible I need to use moby instead - https://github.com/moby/moby/discussions/50472

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type ContainerInfo struct {
	ID    string
	Name  string
	Image string
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

	err = r.updateInfo()
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Resolver) Resolve(cgroupID uint64) *ContainerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Maybe search if container not found?
	return r.cache[cgroupID]
}

func (r *Resolver) updateInfo() error {
	ctx := context.Background()
	containers, err := r.docker.ContainerList(ctx, container.ListOptions{})

	if err != nil {
		return err
	}

	for _, container := range containers {
		// Get init PID

		inspect, err := r.docker.ContainerInspect(ctx, container.ID)
		if err != nil {
			return err
		}
		pid := inspect.State.Pid

		// Find cgroup ID from /proc/
		cgroupID, err := getCgroupID(pid)
		if err != nil {
			return err
		}

		info := &ContainerInfo{
			ID:    container.ID,
			Name:  strings.TrimPrefix(inspect.Name, "/"),
			Image: container.Image,
		}

		r.mu.Lock()
		r.cache[cgroupID] = info
		r.mu.Unlock()
	}

	return nil
}

// Read and parse /proc/pid/cgroup
func getCgroupID(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return 0, err
	}

	// Example line: 0::/user.slice/user-1000.slice/session-2.scope

	line := strings.TrimSpace(string(data))
	parts := strings.SplitN(line, "::", 2)
	cgroupPath := parts[1]

	fullPath := filepath.Join("/sys/fs/cgroup", cgroupPath)
	var stat syscall.Stat_t
	err = syscall.Stat(fullPath, &stat)
	if err != nil {
		return 0, err
	}

	return stat.Ino, nil
}

// Monitor docker events
func (r *Resolver) MonitorEvents(ctx context.Context) {
	eventCh, errCh := r.docker.Events(ctx, events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("event", "start"),
			filters.Arg("event", "die"),
		),
	})
	for {
		select {
		case event := <-eventCh:
			switch event.Action {
			case "start":
				time.Sleep(500 * time.Millisecond)
				r.updateInfo()
			case "die":
				// TODO: remove from cache
			}
		case err := <-errCh:
			slog.Error("error while monitoring events", "error", err)
			return
		case <-ctx.Done():
			return
		}
	}
}
