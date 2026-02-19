package coremain

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/mlog"
)

type serverFlags struct {
	c         string
	dir       string
	cpu       int
	asService bool
}

var rootCmd = &cobra.Command{
	Use: "mosdns",
}

func init() {
	sf := new(serverFlags)
	startCmd := &cobra.Command{
		Use:   "start [-c config_file] [-d working_dir]",
		Short: "Start mosdns main program.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sf.asService {
				svc, err := service.New(&serverService{f: sf}, svcCfg)
				if err != nil {
					return fmt.Errorf("failed to init service, %w", err)
				}
				return svc.Run()
			}
			return StartServer(sf)
		},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
	}
	rootCmd.AddCommand(startCmd)
	fs := startCmd.Flags()
	fs.StringVarP(&sf.c, "config", "c", "", "config file")
	fs.StringVarP(&sf.dir, "dir", "d", "", "working dir")
	fs.IntVar(&sf.cpu, "cpu", 0, "set runtime.GOMAXPROCS")
	fs.BoolVar(&sf.asService, "as-service", false, "start as a service")
	fs.MarkHidden("as-service")

	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage mosdns as a system service.",
	}
	serviceCmd.PersistentPreRunE = initService
	serviceCmd.AddCommand(
		newSvcInstallCmd(),
		newSvcUninstallCmd(),
		newSvcStartCmd(),
		newSvcStopCmd(),
		newSvcRestartCmd(),
		newSvcStatusCmd(),
	)
	rootCmd.AddCommand(serviceCmd)
}

func AddSubCmd(c *cobra.Command) {
	rootCmd.AddCommand(c)
}

func Run() error {
	return rootCmd.Execute()
}

func StartServer(sf *serverFlags) error {
	if sf.cpu > 0 {
		runtime.GOMAXPROCS(sf.cpu)
	}

	if len(sf.dir) > 0 {
		err := os.Chdir(sf.dir)
		if err != nil {
			return fmt.Errorf("failed to change the current working directory, %w", err)
		}
		mlog.L().Info("working directory changed", zap.String("path", sf.dir))
	}

	cfg, fileUsed, err := loadConfig(sf.c)
	if err != nil {
		return fmt.Errorf("fail to load config, %w", err)
	}

	if err := mergeInclude(cfg, 0, []string{fileUsed}); err != nil {
		return fmt.Errorf("failed to load sub config file, %w", err)
	}

	if err := RunMosdns(cfg); err != nil {
		return fmt.Errorf("mosdns exited, %w", err)
	}
	return nil
}

// loadConfig load a config from a file. If filePath is empty, it will
// automatically search and load a file which name start with "config".
func loadConfig(filePath string) (*Config, string, error) {
	v := viper.New()

	if len(filePath) > 0 {
		v.SetConfigFile(filePath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, "", fmt.Errorf("failed to read config: %w", err)
	}

	decoderOpt := func(cfg *mapstructure.DecoderConfig) {
		cfg.ErrorUnused = true
		cfg.TagName = "yaml"
		cfg.WeaklyTypedInput = true
	}

	cfg := new(Config)
	if err := v.Unmarshal(cfg, decoderOpt); err != nil {
		return nil, "", fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return cfg, v.ConfigFileUsed(), nil
}

func mergeInclude(cfg *Config, depth int, paths []string) error {
	depth++
	if depth > 8 {
		return fmt.Errorf("maximum include depth reached, include path is %s", strings.Join(paths, " -> "))
	}

	includedCfg := new(Config)
	for _, subCfgFile := range cfg.Include {
		subPaths := append(paths, subCfgFile)
		mlog.L().Info("reading sub config", zap.String("file", subCfgFile))
		subCfg, _, err := loadConfig(subCfgFile)
		if err != nil {
			return fmt.Errorf("failed to load sub config, %w", err)
		}
		if err := mergeInclude(subCfg, depth, subPaths); err != nil {
			return err
		}

		includedCfg.DataProviders = append(includedCfg.DataProviders, subCfg.DataProviders...)
		includedCfg.Plugins = append(includedCfg.Plugins, subCfg.Plugins...)
		includedCfg.Servers = append(includedCfg.Servers, subCfg.Servers...)
	}

	cfg.DataProviders = append(includedCfg.DataProviders, cfg.DataProviders...)
	cfg.Plugins = append(includedCfg.Plugins, cfg.Plugins...)
	cfg.Servers = append(includedCfg.Servers, cfg.Servers...)
	return nil
}
