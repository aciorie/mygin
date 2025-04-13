package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	Port        int    `mapstructure:"port"`
	LogLevel    string `mapstructure:"log_level"`
	DatabaseURL string `mapstructure:"database_url"`
}

var AppConfig Config

func InitConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			fmt.Println("No config file found, using default values")
			// Set default values
			viper.SetDefault("port", 8080)
			viper.SetDefault("log_level", "debug")
		} else {
			// Other types of errors
			panic(fmt.Errorf("fatal error config file:%s", err))
		}
	}

	if err := viper.Unmarshal(&AppConfig); err != nil {
		panic(fmt.Errorf("unable to decode into struct, %v", err))
	}
}
