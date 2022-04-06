package config

import (
	"errors"

	"github.com/cjlapao/common-go/execution_context"
	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/tls-certificate-generator-go/constants"
	"github.com/cjlapao/tls-certificate-generator-go/entities"
	"gopkg.in/yaml.v2"
)

var ctx = execution_context.Get()
var config = ctx.Configuration

type Config struct {
	Root         []*entities.RootCertificate `json:"rootCertificates" yaml:"rootCertificates"`
	OutputToFile bool                        `json:"outputToFile" yaml:"outputToFile"`
}

func Init() *Config {
	config := Config{
		Root: make([]*entities.RootCertificate, 0),
	}
	return &config
}

func (c *Config) ReadFromFile() error {
	fileName := config.GetString("CONFIG_PATH")
	if fileName == "" {
		fileName = ".\\config.yml"
	}

	if !helper.FileExists(fileName) {
		return errors.New("file not found")
	}

	yamlFile, err := helper.ReadFromFile(fileName)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(yamlFile, c)

	if c.OutputToFile {
		config.UpsertKey(constants.OUTPUT_TO_FILE, c.OutputToFile)
	}

	return nil
}

func (c *Config) SaveToFile() error {
	fileName := config.GetString("CONFIG_PATH")
	if fileName == "" {
		fileName = ".\\config.yml"
	}

	if helper.FileExists(fileName) {
		helper.DeleteFile(fileName)
	}

	yamlFile, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	helper.WriteToFile(string(yamlFile), fileName)

	return nil
}
