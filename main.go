package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cjlapao/common-go/execution_context"
	"github.com/cjlapao/common-go/helper"
	"github.com/cjlapao/common-go/log"
	"github.com/cjlapao/common-go/version"
	"github.com/cjlapao/go-template/startup"
)

var ctx = execution_context.Get()
var logger = log.Get()
var config = execution_context.Get().Configuration

func main() {
	ctx.Services.Version.Major = 0
	ctx.Services.Version.Minor = 0
	ctx.Services.Version.Build = 0
	ctx.Services.Version.Rev = 1
	ctx.Services.Version.Name = "TLS Certificate Generator"
	ctx.Services.Version.Author = "Carlos Lapao"
	ctx.Services.Version.License = "MIT"
	getVersion := helper.GetFlagSwitch("version", false)
	if getVersion {
		format := helper.GetFlagValue("o", "json")
		switch strings.ToLower(format) {
		case "json":
			fmt.Println(ctx.Services.Version.PrintVersion(int(version.JSON)))
		case "yaml":
			fmt.Println(ctx.Services.Version.PrintVersion(int(version.JSON)))
		default:
			fmt.Println("Please choose a valid format, this can be either json or yaml")
		}
		os.Exit(0)
	}

	ctx.Services.Version.PrintAnsiHeader()

	configFile := helper.GetFlagValue("config", "")
	if configFile != "" {
		logger.Command("Loading configuration from " + configFile)
		config.LoadFromFile(configFile)
	}

	defer func() {
	}()

	startup.Init()
}
