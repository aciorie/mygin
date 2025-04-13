package registry

import (
	"fmt"
	"sync"
)

// ServiceRegistry defines the interface for service registration and discovery.
type ServiceRegistry interface {
	Register(name, address string) error
	Deregister(name string) error
	Discover(name string) (string, error)
	List() map[string]string
}

// inMemoryRegistry is a simple in-memory implementation.
type inMemoryRegistry struct {
	mu       sync.RWMutex
	services map[string]string // service name -> address
}

// NewInMemoryRegistry creates a new in-memory registry.
func NewInMemoryRegistry() ServiceRegistry {
	return &inMemoryRegistry{
		services: make(map[string]string),
	}
}

func (r *inMemoryRegistry) Register(name, address string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[name] = address
	fmt.Printf("Registry: Registered service '%s' at '%s'\n", name, address)
	return nil
}

func (r *inMemoryRegistry) Deregister(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.services[name]; !ok {
		return fmt.Errorf("service '%s' not found", name)
	}
	delete(r.services, name)
	fmt.Printf("Registry: Deregistered service '%s'\n", name)
	return nil
}

func (r *inMemoryRegistry) Discover(name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	address, ok := r.services[name]
	if !ok {
		return "", fmt.Errorf("service '%s' not found", name)
	}
	return address, nil
}

func (r *inMemoryRegistry) List() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy to avoid external modification
	list := make(map[string]string, len(r.services))
	for k, v := range r.services {
		list[k] = v
	}
	return list
}
