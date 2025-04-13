package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	HTTPPort    int    `mapstructure:"http_port"` // Renamed from port
	GRPCPort    int    `mapstructure:"grpc_port"`
	LogLevel    string `mapstructure:"log_level"`
	DatabaseURL string `mapstructure:"database_url"`
	ServiceName string `mapstructure:"service_name"` // Added for registration
	// Add JWT Secret Key here instead of hardcoding
	JwtSecret string `mapstructure:"jwt_secret"`
}

var AppConfig Config

func InitConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Environment variable overrides
	viper.SetEnvPrefix("MYAPP") // Example prefix
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set default values
	viper.SetDefault("http_port", 8080)
	viper.SetDefault("grpc_port", 50051)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("service_name", "user-center")
	viper.SetDefault("jwt_secret", "default-very-insecure-secret-key") // CHANGE THIS IN PRODUCTION

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("Config file not found, using defaults and environment variables.")
		} else {
			panic(fmt.Errorf("fatal error reading config file: %w", err))
		}
	}

	if err := viper.Unmarshal(&AppConfig); err != nil {
		panic(fmt.Errorf("unable to decode config into struct: %w", err))
	}

	// Update global auth key if it's still global (better to inject)
	// if AppConfig.JwtSecret != "" && AppConfig.JwtSecret != "default-very-insecure-secret-key" {
	// 	auth.SetSigningKey([]byte(AppConfig.JwtSecret)) // Need a setter in auth pkg
	// } else if AppConfig.JwtSecret == "default-very-insecure-secret-key" {
	// 	fmt.Println("WARNING: Using default insecure JWT secret key!")
	// }
}
