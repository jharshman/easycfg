package easycfg

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// GnuPGHome points to the default location on the filesystem for the GnuPG keyrings.
// If using a non-standard location, this can be set at compile time via linker flags.
var GnuPGHome = "/root/.gnupg"

var standard *pflag.FlagSet
var encrypted *pflag.FlagSet
var gpgEntities openpgp.EntityList
var once sync.Once

type ProgramOpts func()

// WithStringVar is a simple wrapper around pflag.StringVar. It allows this package to present its unique way of setting
// program arguments to the user while still leaning on spf13/pflag for flag setting logic.
func WithStringVar(opt *string, name string, defaultValue string, usage string) ProgramOpts {
	return func() {
		standard.StringVar(opt, name, defaultValue, usage)
	}
}

// WithIntVar is a simple wrapper around pflag.IntVar. It allows this package to present its unique way of setting
// program arguments to the user while still leaning on spf13/pflag for flag setting logic.
func WithIntVar(opt *int, name string, defaultValue int, usage string) ProgramOpts {
	return func() {
		standard.IntVar(opt, name, defaultValue, usage)
	}
}

// WithBoolVar is a simple wrapper around pflag.BoolVar. It allows this package to present its unique way of setting
// program arguments to the user while still leaning on spf13/pflag for flag setting logic.
func WithBoolVar(opt *bool, name string, defaultValue bool, usage string) ProgramOpts {
	return func() {
		standard.BoolVar(opt, name, defaultValue, usage)
	}
}

// WithGPGEncryptedValueFromFile is a simple wrapper around pflag.StringVar. It allows this package to present its
// unique way of setting program arguments to the user while still leaning on spf13/pflag for flag setting logic.
// This function uses a separate pflag.FlagSet that is used to identify encrypted values.
func WithGPGEncryptedValueFromFile(opt *string, name string, defaultValue string, usage string) ProgramOpts {
	return func() {
		encrypted.StringVar(opt, name, defaultValue, usage)
	}
}

// InitConfig initializes the program's configuration.
func InitConfig(serviceName string, opts ...ProgramOpts) error {

	if len(serviceName) == 0 {
		return fmt.Errorf("required parameter not set")
	}

	once.Do(func() {
		standard = pflag.NewFlagSet("standard", pflag.ExitOnError)
		encrypted = pflag.NewFlagSet("encrypted", pflag.ExitOnError)

		// set up gpg keyring
		secringPath := filepath.Join(GnuPGHome, "secring.gpg")
		pubringPath := filepath.Join(GnuPGHome, "pubring.gpg")

		secring, _ := os.Open(secringPath)
		defer secring.Close()
		pubring, _ := os.Open(pubringPath)
		defer pubring.Close()

		se, _ := openpgp.ReadKeyRing(secring)
		pe, _ := openpgp.ReadKeyRing(pubring)

		gpgEntities = append(se, pe...)
	})

	for _, opt := range opts {
		opt()
	}

	// todo: Need to bind options to settings file entries
	standard.VisitAll(func(flag *pflag.Flag) {
		bindEnv(flag)
	})
	encrypted.VisitAll(func(flag *pflag.Flag) {
		bindEnv(flag)
	})

	pflag.Parse()

	viper.SetEnvPrefix(serviceName)
	// todo: handle GPG encrypted information and store unencrypted values...
	// variables pointing to gpg encrypted assets are in the encrypted FlagSet.
	encrypted.VisitAll(func(flag *pflag.Flag) {
		name := flag.Name
		value, _ := gpgDecodeFromFile(flag.Value.String())
		viper.Set(name, value)
	})

	return nil
}

// gpgDecodeFromFile decodes the encrypted value from the file at the file path provided.
func gpgDecodeFromFile(fname string) (string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer f.Close()

	msg, err := openpgp.ReadMessage(f, gpgEntities, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		return []byte{}, nil
	}, &packet.Config{})
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(msg.UnverifiedBody)
	if err != nil {
		return "", err
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	return string(data), nil
}

// bindEnv binds the defined flags to properly formatted environment.
func bindEnv(flag *pflag.Flag) {
	flagName := flag.Name
	envName := strings.ReplaceAll(flagName, "-", "_")
	envName = strings.ToUpper(flagName)
	_ = viper.BindEnv(flagName, envName)
}
