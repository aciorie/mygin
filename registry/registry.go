package registry

import (
	consulapi "github.com/hashicorp/consul/api"
)

// ServiceRegistry defines the interface for service registration and discovery.
type ServiceRegistry interface {
	// Register registers a specific service instance with Consul.
	// id: Unique identifier for this instance (e.g., serviceName + hostname + port).
	// name: Logical name of the service (e.g., "user-center-grpc").
	// address: IP or hostname where the service listens.
	// port: Port number where the service listens.
	// tags: Optional tags for filtering.
	// check: Health check configuration.
	Register(id, name, address string, port int, tags []string, check *consulapi.AgentServiceCheck) error

	// Deregister removes a service instance using its unique ID.
	Deregister(id string) error

	// Discover finds healthy instances of a service by name and optional tag.
	// Returns a list of "host:port" strings.
	Discover(name string, tag string) ([]string, error)

	// List retrieves a map of service names to some representation (e.g., tags).
	List() (map[string]string, error)
}
