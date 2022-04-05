package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cjlapao/common-go/executionctx"
	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/common-go/version"
	"github.com/cjlapao/go-template/startup"
)

var svc = executionctx.NewServiceProvider()

func main() {
	svc.Version.Minor = 1
	svc.Version.Name = "GoLang Template"
	svc.Version.Author = "Carlos Lapao"
	svc.Version.License = "MIT"
	getVersion := helper.GetFlagSwitch("version", false)
	if getVersion {
		format := helper.GetFlagValue("o", "json")
		switch strings.ToLower(format) {
		case "json":
			fmt.Println(svc.Version.PrintVersion(int(version.JSON)))
		case "yaml":
			fmt.Println(svc.Version.PrintVersion(int(version.JSON)))
		default:
			fmt.Println("Please choose a valid format, this can be either json or yaml")
		}
		os.Exit(0)
	}

	svc.Version.PrintAnsiHeader()

	configFile := helper.GetFlagValue("config", "")
	if configFile != "" {
		svc.Logger.Command("Loading configuration from " + configFile)
		svc.Context.Configuration.LoadFromFile(configFile)
	}

	defer func() {
	}()

	startup.Init()
}
