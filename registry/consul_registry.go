package registry

import (
	"fmt"
	"mygin-restful/config"

	consulapi "github.com/hashicorp/consul/api"
	"go.uber.org/zap"
)

type consulRegistry struct {
	client *consulapi.Client
	logger *zap.SugaredLogger
}

// Ensure consulRegistry implements ServiceRegistry
var _ ServiceRegistry = (*consulRegistry)(nil)

// NewConsulRegistry creates a new registry backed by Consul.
func NewConsulRegistry(logger *zap.SugaredLogger) (ServiceRegistry, error) {
	consulConfig := consulapi.DefaultConfig()
	consulConfig.Address = config.AppConfig.Consul.Address // Use address from config

	client, err := consulapi.NewClient(consulConfig)
	if err != nil {
		logger.Errorw("Failed to create Consul client", "address", consulConfig.Address, "error", err)
		return nil, fmt.Errorf("failed to create consul client: %w", err)
	}

	// Optional: Ping Consul agent to check connectivity
	_, err = client.Agent().NodeName()
	if err != nil {
		logger.Errorw("Failed to connect to Consul agent", "address", consulConfig.Address, "error", err)
		return nil, fmt.Errorf("cannot connect to consul agent at %s: %w", consulConfig.Address, err)
	}
	logger.Infow("Successfully connected to Consul agent", "address", consulConfig.Address)

	return &consulRegistry{
		client: client,
		logger: logger.Named("ConsulRegistry"), // Add a name scope to the logger
	}, nil
}

// Register registers a service instance with Consul, including a health check.
func (r *consulRegistry) Register(id, name, address string, port int, tags []string, check *consulapi.AgentServiceCheck) error {
	reg := &consulapi.AgentServiceRegistration{
		ID:      id,                                          // Unique ID for this service instance
		Name:    name,                                        // Service Name (e.g., "user-center-grpc")
		Tags:    tags,                                        // Optional tags
		Port:    port,                                        // Service port
		Address: address,                                     // Service IP address or hostname
		Check:   check,                                       // Health Check configuration
		Meta:    map[string]string{"protocol": check.Method}, // Example Meta
	}

	err := r.client.Agent().ServiceRegister(reg)
	if err != nil {
		r.logger.Errorw("Failed to register service with Consul", "service_id", id, "service_name", name, "address", address, "port", port, "error", err)
		return fmt.Errorf("failed to register service '%s': %w", name, err)
	}
	r.logger.Infow("Successfully registered service with Consul", "service_id", id, "service_name", name, "address", address, "port", port)
	return nil
}

// Deregister removes a service instance from Consul.
func (r *consulRegistry) Deregister(id string) error {
	err := r.client.Agent().ServiceDeregister(id)
	if err != nil {
		r.logger.Errorw("Failed to deregister service from Consul", "service_id", id, "error", err)
		return fmt.Errorf("failed to deregister service '%s': %w", id, err)
	}
	r.logger.Infow("Successfully deregistered service from Consul", "service_id", id)
	return nil
}

// Discover finds healthy instances of a service in Consul.
// It returns a list of addresses (e.g., "host:port").
func (r *consulRegistry) Discover(name string, tag string) ([]string, error) {
	// PassingOnly=true returns only services with passing health checks.
	// Use tag to filter if needed, otherwise leave empty.
	instances, _, err := r.client.Health().Service(name, tag, true, nil)
	if err != nil {
		r.logger.Warnw("Failed to discover service from Consul", "service_name", name, "tag", tag, "error", err)
		return nil, fmt.Errorf("failed to discover service '%s': %w", name, err)
	}

	if len(instances) == 0 {
		r.logger.Warnw("No healthy instances found for service", "service_name", name, "tag", tag)
		return nil, fmt.Errorf("no healthy instances found for service '%s'", name)
	}

	addrs := make([]string, 0, len(instances))
	for _, inst := range instances {
		// Prefer Service.Address, fallback to Node.Address
		addr := inst.Service.Address
		if addr == "" {
			addr = inst.Node.Address
		}
		addrs = append(addrs, fmt.Sprintf("%s:%d", addr, inst.Service.Port))
	}
	r.logger.Debugw("Discovered healthy service instances", "service_name", name, "tag", tag, "count", len(addrs), "addresses", addrs)
	return addrs, nil
}

// List is less common with Consul as discovery is dynamic, but could list registered services.
// For simplicity, we can omit a full implementation or just return service names.
func (r *consulRegistry) List() (map[string]string, error) {
	services, _, err := r.client.Catalog().Services(nil)
	if err != nil {
		r.logger.Errorw("Failed to list services from Consul catalog", "error", err)
		return nil, fmt.Errorf("failed to list services from consul: %w", err)
	}
	// This map is service name -> list of tags (just an example representation)
	serviceMap := make(map[string]string)
	for name, tags := range services {
		serviceMap[name] = fmt.Sprintf("%v", tags)
	}
	return serviceMap, nil
}

// --- Helper functions to define specific Health Checks ---

// CreateHTTPCheck creates a Consul HTTP health check configuration.
// serviceHost: The address Consul should *hit* for the check (usually localhost or container IP).
// checkPath: The HTTP path for the health check (e.g., "/health").
// interval: How often to run the check (e.g., "10s").
// timeout: How long to wait for a response (e.g., "1s").
func CreateHTTPCheck(serviceID, serviceHost string, servicePort int, checkPath string, interval, timeout string) *consulapi.AgentServiceCheck {
	return &consulapi.AgentServiceCheck{
		CheckID:                        fmt.Sprintf("check_%s_http", serviceID),
		Name:                           fmt.Sprintf("HTTP Check for %s", serviceID),
		HTTP:                           fmt.Sprintf("http://%s:%d%s", serviceHost, servicePort, checkPath),
		Method:                         "GET", // Or HEAD
		Interval:                       interval,
		Timeout:                        timeout,
		DeregisterCriticalServiceAfter: "1m", // Automatically deregister after 1 minute of being critical
	}
}

// CreateGRPCSCheck creates a Consul gRPC health check configuration.
// Requires the gRPC service to implement the gRPC Health Checking Protocol.
// grpcTarget: The address:port Consul should use for the check.
// interval: How often to run the check (e.g., "10s").
// timeout: How long to wait for a response (e.g., "1s").
// useTLS: Set to true if the gRPC service uses TLS.
func CreateGRPCSCheck(serviceID, grpcTarget string, interval, timeout string, useTLS bool) *consulapi.AgentServiceCheck {
	return &consulapi.AgentServiceCheck{
		CheckID:                        fmt.Sprintf("check_%s_grpc", serviceID),
		Name:                           fmt.Sprintf("gRPC Check for %s", serviceID),
		GRPC:                           grpcTarget,
		GRPCUseTLS:                     useTLS,
		Interval:                       interval,
		Timeout:                        timeout,
		DeregisterCriticalServiceAfter: "1m",
	}
}
