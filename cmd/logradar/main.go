package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/xoelrdgz/logradar/internal/adapters/detection"
	"github.com/xoelrdgz/logradar/internal/adapters/input"
	"github.com/xoelrdgz/logradar/internal/adapters/output"
	"github.com/xoelrdgz/logradar/internal/app"
	"github.com/xoelrdgz/logradar/internal/ports"
	"github.com/xoelrdgz/logradar/internal/tui"
)

var (
	cfgFile      string
	logFile      string
	noTUI        bool
	jsonOut      bool
	fullAnalysis bool
	demoMode     bool
	demoRate     int
	workers      int

	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "logradar",
	Short: "Production-grade HTTP log threat detection",
	Long: `LogRadar is a production-grade, real-time threat detection system 
for HTTP access logs. It monitors log files, detects attack patterns, 
and displays results in an interactive terminal interface.

Detection Capabilities:
  - Signature Analysis: SQLi, XSS, Path Traversal, RCE
  - Behavioral Analysis: Brute Force, Rate Limiting, DoS
  - Threat Intelligence: Known malicious IP correlation

Performance:
  - Throughput: >50,000 lines/second
  - Memory: Optimized for 24/7 operation
  - Concurrency: Configurable worker pool`,
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Start threat detection on log source",
	Long: `Start real-time analysis of the specified log file.
The analyzer will tail the log file and detect threats in real-time.

Examples:
  logradar analyze --log /var/log/nginx/access.log
  logradar analyze --log ./access.log --no-tui --workers 16
  logradar analyze --demo --demo-rate 10000
  logradar analyze --log ./access.log --json`,
	RunE: runAnalyze,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("LogRadar %s\n", Version)
		fmt.Printf("Commit:  %s\n", Commit)
		fmt.Printf("Built:   %s\n", BuildTime)
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./configs/config.yaml)")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log", "l", "", "log file to analyze")
	rootCmd.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "disable TUI, output to stdout")
	rootCmd.PersistentFlags().BoolVar(&jsonOut, "json", false, "output alerts as JSON")
	rootCmd.PersistentFlags().BoolVar(&fullAnalysis, "full", false, "analyze entire file from beginning")
	rootCmd.PersistentFlags().BoolVar(&demoMode, "demo", false, "demo mode: generate synthetic traffic")
	rootCmd.PersistentFlags().IntVar(&demoRate, "demo-rate", 1000, "demo mode: entries per second")
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", 16, "number of worker goroutines")

	viper.BindPFlag("log.path", rootCmd.PersistentFlags().Lookup("log"))
	viper.BindPFlag("tui.enabled", rootCmd.PersistentFlags().Lookup("no-tui"))
	viper.BindPFlag("output.json.enabled", rootCmd.PersistentFlags().Lookup("json"))
	viper.BindPFlag("workers.count", rootCmd.PersistentFlags().Lookup("workers"))

	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/logradar")
	}

	viper.SetDefault("log.path", "./testdata/sample.log")
	viper.SetDefault("workers.count", 16)
	viper.SetDefault("workers.buffer_size", 50000)
	viper.SetDefault("tui.enabled", true)
	viper.SetDefault("output.json.enabled", false)
	viper.SetDefault("output.json.stdout", true)
	viper.SetDefault("output.metrics.enabled", true)
	viper.SetDefault("output.metrics.port", ":9090")
	viper.SetDefault("detection.behavioral.brute_force.threshold", 10)
	viper.SetDefault("detection.behavioral.brute_force.window_seconds", 60)
	viper.SetDefault("detection.behavioral.rate_limit.threshold", 100)
	viper.SetDefault("detection.behavioral.rate_limit.window_seconds", 10)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Warn().Err(err).Msg("Error reading config file")
		}
	}

	viper.SetEnvPrefix("LOGRADAR")
	viper.AutomaticEnv()
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	level := viper.GetString("logging.level")
	switch level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if noTUI {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
		})
	} else {
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	}
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	setupLogging()

	logPath := viper.GetString("log.path")
	if logFile != "" {
		logPath = logFile
	}

	if logPath == "" && !demoMode {
		return fmt.Errorf("log file path required: use --log or --demo flag")
	}

	sourceName := "DEMO"
	if !demoMode {
		sourceName = filepath.Base(logPath)
	}

	if demoMode {
		log.Info().
			Int("rate", demoRate).
			Int("workers", viper.GetInt("workers.count")).
			Bool("tui", !noTUI).
			Msg("LogRadar started (demo mode)")
	} else {
		log.Info().
			Str("source", logPath).
			Int("workers", viper.GetInt("workers.count")).
			Bool("tui", !noTUI).
			Msg("LogRadar started")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var reader ports.LogReader
	if demoMode {
		config := input.DemoConfig{
			Rate:          demoRate,
			BufferSize:    viper.GetInt("workers.buffer_size"),
			AttackPercent: 15,
		}
		reader = input.NewDemoGenerator(config)
		log.Debug().Int("rate", demoRate).Msg("Demo generator initialized")
	} else {
		parser := input.NewCombinedLogParser()
		tailer := input.NewFileTailer(logPath, parser, viper.GetInt("workers.buffer_size"))
		if fullAnalysis {
			tailer.SetFromBeginning(true)
			log.Info().Msg("Full analysis mode: reading from beginning")
		}
		reader = tailer
	}

	var detectors []ports.ThreatDetector

	sigDetector := detection.NewSignatureDetector(nil)
	detectors = append(detectors, sigDetector)
	log.Debug().Int("patterns", sigDetector.PatternCount()).Msg("Signature patterns loaded")

	behavConfig := detection.BehavioralConfig{
		ShardCount:          16,
		BruteForceThreshold: viper.GetInt("detection.behavioral.brute_force.threshold"),
		BruteForceWindow:    int64(viper.GetInt("detection.behavioral.brute_force.window_seconds")),
		BruteForceStatus:    401,
		RateLimitThreshold:  viper.GetInt("detection.behavioral.rate_limit.threshold"),
		RateLimitWindow:     int64(viper.GetInt("detection.behavioral.rate_limit.window_seconds")),
		CleanupInterval:     30 * time.Second,
	}
	behavDetector := detection.NewBehavioralDetector(behavConfig)
	detectors = append(detectors, behavDetector)
	defer behavDetector.Stop()

	threatIntelConfig := detection.DefaultThreatIntelConfig()
	threatIntelConfig.Filepath = viper.GetString("threat_intel.malicious_ips_file")
	if threatIntelConfig.Filepath == "" {
		threatIntelConfig.Filepath = "./testdata/malicious_ips.txt"
	}
	threatIntel := detection.NewThreatIntelligence(threatIntelConfig)
	if err := threatIntel.Load(ctx); err != nil {
		log.Warn().Err(err).Msg("Failed to load threat intelligence")
	} else {
		log.Debug().Int("count", threatIntel.Count()).Msg("Threat intelligence loaded")
	}
	threatIntelDetector := detection.NewThreatIntelDetector(threatIntel)
	detectors = append(detectors, threatIntelDetector)

	var alerters []ports.Alerter
	memAlerter := output.NewMemoryAlerter(100)
	alerters = append(alerters, memAlerter)

	if jsonOut || viper.GetBool("output.json.enabled") {
		jsonConfig := output.JSONAlerterConfig{
			Stdout: viper.GetBool("output.json.stdout") || jsonOut,
			Pretty: true,
		}
		if path := viper.GetString("output.json.path"); path != "" && !jsonOut {
			jsonConfig.FilePath = path
			jsonConfig.Stdout = false
		}
		jsonAlerter, err := output.NewJSONAlerter(jsonConfig)
		if err != nil {
			return fmt.Errorf("failed to create JSON alerter: %w", err)
		}
		alerters = append(alerters, jsonAlerter)
		defer jsonAlerter.Close()
	}

	analyzer := app.NewAnalyzer(reader, detectors, alerters)

	workerConfig := app.WorkerPoolConfig{
		WorkerCount: viper.GetInt("workers.count"),
		BufferSize:  viper.GetInt("workers.buffer_size"),
	}
	if workers > 0 {
		workerConfig.WorkerCount = workers
	}
	analyzer.SetWorkerConfig(workerConfig)

	if viper.GetBool("output.metrics.enabled") {
		promMetrics := output.NewPrometheusMetrics("logradar", analyzer.InternalMetrics())
		analyzer.AddAlertSubscriber(promMetrics)
		analyzer.AddProcessingObserver(promMetrics)

		metricsConfig := output.MetricsConfig{
			Port:       viper.GetString("output.metrics.port"),
			Path:       "/metrics",
			HealthPath: "/ready",
		}
		if err := promMetrics.StartServer(metricsConfig); err != nil {
			log.Warn().Err(err).Msg("Failed to start metrics server")
		} else {
			log.Debug().Str("addr", metricsConfig.Port).Msg("Metrics server started")
		}
		defer promMetrics.StopServer()
	}

	if noTUI {
		log.Info().Msg("Running in console mode")
		analyzer.AddAlertSubscriber(memAlerter)
		return analyzer.Run(ctx)
	}

	tuiApp := tui.NewApp()
	tuiApp.SetLogSource(sourceName)
	analyzer.AddAlertSubscriber(tuiApp)
	go func() {
		if err := analyzer.Start(ctx); err != nil {
			log.Error().Err(err).Msg("Analyzer error")
		}
	}()

	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tuiApp.SendMetrics(analyzer.Metrics())
			}
		}
	}()

	var tuiErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error().Interface("panic", r).Msg("TUI panic recovered")
				tuiErr = fmt.Errorf("TUI panic: %v", r)
			}
		}()
		tuiErr = tuiApp.Run()
	}()

	cancel()
	log.Info().Msg("Shutting down...")

	shutdownDone := make(chan struct{})
	go func() {
		analyzer.Stop()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		log.Debug().Msg("Shutdown complete")
	case <-time.After(5 * time.Second):
		log.Warn().Msg("Shutdown timeout, forcing exit")
	}

	return tuiErr
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
