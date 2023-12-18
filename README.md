# EasyCFG

A lightweight package around `pflag` and `viper` providing a easy way to configure program options and tie it together
with a settings file and environment variables. Additional support for GPG encrypted values has been added.

### Usage

Example:
```go
package main

import "github.com/jharshman/easycfg"

func main() {
	var(
		port int
		debug bool
		settingsFile string
		serviceAccount string
	)
	
	easycfg.InitConfig("my-cool-service", settingsFile, 
		easycfg.WithIntVar(&port, "port", 8080, "server bind port"),
		easycfg.WithBoolVar(&debug, "debug", false, "set debug logging"),
		easycfg.WithGPGEncryptedValueFromFile(&serviceAccount, "service-account", "", "service account")
	)
	
}
```

### Non-Standard GnuPG Home Directory

The default for GnuPG's home directory is set to `/root/.gnupg`. If you need to use a different GnuPG home directory,
you can set it via linker flag: `-ldflags="-X github.com/jharshman/easycfg.GnuPGHome=/some/other/directory"`.
