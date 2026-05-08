package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/xoelrdgz/logradar/internal/adapters/detection"
	"github.com/xoelrdgz/logradar/internal/adapters/input"
	"github.com/xoelrdgz/logradar/internal/adapters/output"
	"github.com/xoelrdgz/logradar/internal/app"
	"github.com/xoelrdgz/logradar/internal/domain"
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
	stdinMode    bool
	batchMode    bool
	workers      int

	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

type threatsDetectedError struct {
	count int64
}

func (e threatsDetectedError) Error() string {
	return fmt.Sprintf("threats detected: %d alerts emitted", e.count)
}

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
	rootCmd.PersistentFlags().BoolVar(&stdinMode, "stdin", false, "read log entries from stdin until EOF")
	rootCmd.PersistentFlags().BoolVar(&batchMode, "batch", false, "process finite input and exit")
	rootCmd.PersistentFlags().IntVarP(&workers, "workers", "w", 16, "number of worker goroutines")

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

	viper.SetDefault("log.path", "./access.log")
	viper.SetDefault("app.shutdown_timeout_seconds", 5)
	viper.SetDefault("log.checkpoint.enabled", false)
	viper.SetDefault("log.checkpoint.path", "")
	viper.SetDefault("workers.count", 16)
	viper.SetDefault("workers.buffer_size", 50000)
	viper.SetDefault("workers.submit_timeout_ms", 100)
	viper.SetDefault("workers.overflow_path", "")
	viper.SetDefault("workers.quarantine_path", "")
	viper.SetDefault("tui.enabled", true)
	viper.SetDefault("output.json.enabled", false)
	viper.SetDefault("output.json.stdout", true)
	viper.SetDefault("output.json.redact_sensitive", true)
	viper.SetDefault("output.json.include_raw_log", true)
	viper.SetDefault("output.json.max_alert_bytes", 65536)
	viper.SetDefault("output.metrics.enabled", true)
	viper.SetDefault("output.metrics.port", ":9090")
	viper.SetDefault("output.metrics.path", "/metrics")
	viper.SetDefault("output.dedup.enabled", false)
	viper.SetDefault("output.dedup.window_seconds", 60)
	viper.SetDefault("log.format", "combined")
	viper.SetDefault("detection.signatures.enabled", true)
	viper.SetDefault("detection.signatures.rules_file", "")
	viper.SetDefault("detection.behavioral.enabled", true)
	viper.SetDefault("detection.allowlist.ips", []string{})
	viper.SetDefault("detection.allowlist.cidrs", []string{})
	viper.SetDefault("detection.allowlist.path_prefixes", []string{})
	viper.SetDefault("detection.allowlist.user_agent_substrings", []string{})
	viper.SetDefault("threat_intel.enabled", false)
	viper.SetDefault("threat_intel.feed_files", []string{})
	viper.SetDefault("threat_intel.default_ttl_seconds", 0)
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
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
}

func setupLogging(cfg app.RuntimeConfig) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	level := cfg.Logging.Level
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

func configuredParser(format string) (ports.LogParser, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "combined", "clf":
		return input.NewCombinedLogParser(), nil
	case "json":
		return input.NewJSONParser(), nil
	case "auto", "autodetect", "auto-detect":
		return input.NewAutoDetectParser(), nil
	default:
		return nil, fmt.Errorf("unsupported log.format %q: valid values are combined, json or auto", format)
	}
}

type detectorRuntimeStats struct {
	ThreatIntelEntries    int
	ThreatIntelLastReload time.Time
	ThreatIntelFeedErrors int
}

func configuredDetectors(ctx context.Context, cfg app.RuntimeConfig) ([]ports.ThreatDetector, func(), detectorRuntimeStats, error) {
	var detectors []ports.ThreatDetector
	var cleanup []func()
	var stats detectorRuntimeStats

	if cfg.Detection.Signatures.Enabled {
		patterns, err := configuredSignaturePatterns(cfg.Detection.Signatures)
		if err != nil {
			return nil, nil, stats, err
		}
		sigDetector := detection.NewSignatureDetector(patterns)
		detectors = append(detectors, sigDetector)
		log.Debug().Int("patterns", sigDetector.PatternCount()).Msg("Signature patterns loaded")
	}

	if cfg.Detection.Behavioral.Enabled {
		behavConfig := detection.BehavioralConfig{
			ShardCount:          16,
			BruteForceThreshold: cfg.Detection.Behavioral.BruteForce.Threshold,
			BruteForceWindow:    cfg.Detection.Behavioral.BruteForce.WindowSeconds,
			BruteForceStatus:    cfg.Detection.Behavioral.BruteForce.StatusCode,
			RateLimitThreshold:  cfg.Detection.Behavioral.RateLimit.Threshold,
			RateLimitWindow:     cfg.Detection.Behavioral.RateLimit.WindowSeconds,
			CleanupInterval:     30 * time.Second,
		}
		if behavConfig.BruteForceStatus == 0 {
			behavConfig.BruteForceStatus = 401
		}
		behavDetector := detection.NewBehavioralDetector(behavConfig)
		detectors = append(detectors, behavDetector)
		cleanup = append(cleanup, behavDetector.Stop)
	}

	if cfg.ThreatIntel.Enabled {
		threatIntelConfig := detection.DefaultThreatIntelConfig()
		if cfg.ThreatIntel.MaliciousIPsFile != "" {
			threatIntelConfig.Filepath = cfg.ThreatIntel.MaliciousIPsFile
		}
		threatIntelConfig.FeedFiles = cfg.ThreatIntel.FeedFiles
		if cfg.ThreatIntel.BloomFilterSize > 0 {
			threatIntelConfig.BloomSize = cfg.ThreatIntel.BloomFilterSize
		}
		if cfg.ThreatIntel.BloomFalsePositiveRate > 0 {
			threatIntelConfig.FalsePositiveRate = cfg.ThreatIntel.BloomFalsePositiveRate
		}
		if cfg.ThreatIntel.DefaultTTLSeconds > 0 {
			threatIntelConfig.DefaultTTL = time.Duration(cfg.ThreatIntel.DefaultTTLSeconds) * time.Second
		}
		threatIntel := detection.NewThreatIntelligence(threatIntelConfig)
		if err := threatIntel.Load(ctx); err != nil {
			log.Warn().Err(err).Msg("Failed to load threat intelligence")
			stats.ThreatIntelFeedErrors = 1
		} else {
			log.Debug().Int("count", threatIntel.Count()).Msg("Threat intelligence loaded")
			stats.ThreatIntelEntries = threatIntel.Count()
			stats.ThreatIntelLastReload = time.Now()
		}
		detectors = append(detectors, detection.NewThreatIntelDetector(threatIntel))
	}

	if len(detectors) == 0 {
		return nil, nil, stats, fmt.Errorf("no detectors enabled: enable at least one of detection.signatures, detection.behavioral or threat_intel")
	}

	return detectors, func() {
		for _, stop := range cleanup {
			stop()
		}
	}, stats, nil
}

func configuredSignaturePatterns(config app.SignatureRuntimeConfig) ([]*detection.Pattern, error) {
	var patterns []*detection.Pattern
	if config.RulesFile != "" {
		loaded, err := detection.LoadSignatureRulesFile(config.RulesFile)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, loaded...)
	}
	if len(config.Patterns) == 0 {
		if len(patterns) > 0 {
			return patterns, nil
		}
		return nil, nil
	}

	patterns = append(detection.DefaultPatterns(), patterns...)
	for name, expr := range config.Patterns {
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("invalid signature pattern %q: %w", name, err)
		}
		patterns = append(patterns, &detection.Pattern{
			ID:         "configured." + strings.ToLower(strings.ReplaceAll(name, "_", ".")),
			Version:    "1",
			Name:       "Configured - " + name,
			Regex:      compiled,
			ThreatType: configuredThreatType(name),
			RiskScore:  8,
			Level:      domain.AlertLevelWarning,
			Confidence: 0.85,
			Keywords:   strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '_' || r == '-' || r == ' ' }),
		})
	}
	return patterns, nil
}

func configuredThreatType(name string) domain.ThreatType {
	switch strings.ToLower(name) {
	case "sqli", "sql", "sql_injection":
		return domain.ThreatTypeSQLInjection
	case "xss":
		return domain.ThreatTypeXSS
	case "traversal", "path_traversal":
		return domain.ThreatTypePathTraversal
	case "rce":
		return domain.ThreatTypeRCE
	case "lfi":
		return domain.ThreatTypeLFI
	case "log4shell":
		return domain.ThreatTypeLog4Shell
	default:
		return domain.ThreatTypeUnknown
	}
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	cfg := app.LoadRuntimeConfig()

	if cmd.Flags().Changed("log") {
		cfg.Log.Path = logFile
	}
	if cmd.Flags().Changed("workers") {
		cfg.Workers.Count = workers
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	setupLogging(cfg)

	logPath := cfg.Log.Path
	effectiveTUI := cfg.TUI.Enabled && !noTUI && !stdinMode && !batchMode

	if logPath == "" && !demoMode && !stdinMode {
		return fmt.Errorf("log file path required: use --log, --stdin or --demo flag")
	}

	sourceName := "DEMO"
	if stdinMode {
		sourceName = "STDIN"
	} else if !demoMode {
		sourceName = filepath.Base(logPath)
	}

	if demoMode {
		log.Info().
			Int("rate", demoRate).
			Int("workers", cfg.Workers.Count).
			Bool("tui", effectiveTUI).
			Msg("LogRadar started (demo mode)")
	} else if stdinMode {
		log.Info().
			Int("workers", cfg.Workers.Count).
			Bool("batch", batchMode).
			Msg("LogRadar started (stdin mode)")
	} else {
		log.Info().
			Str("source", logPath).
			Int("workers", cfg.Workers.Count).
			Bool("tui", effectiveTUI).
			Msg("LogRadar started")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var reader ports.LogReader
	if demoMode {
		config := input.DemoConfig{
			Rate:          demoRate,
			BufferSize:    cfg.Workers.BufferSize,
			AttackPercent: 15,
		}
		reader = input.NewDemoGenerator(config)
		log.Debug().Int("rate", demoRate).Msg("Demo generator initialized")
	} else {
		parser, err := configuredParser(cfg.Log.Format)
		if err != nil {
			return err
		}
		if stdinMode {
			reader = input.NewStreamReader("stdin", os.Stdin, parser, cfg.Workers.BufferSize)
		} else if batchMode {
			file, err := os.Open(logPath)
			if err != nil {
				return fmt.Errorf("failed to open batch input: %w", err)
			}
			defer file.Close()
			reader = input.NewStreamReader(logPath, file, parser, cfg.Workers.BufferSize)
		} else {
			tailer := input.NewFileTailer(logPath, parser, cfg.Workers.BufferSize)
			tailer.SetCheckpoint(input.CheckpointConfig{
				Enabled: cfg.Log.Checkpoint.Enabled,
				Path:    cfg.Log.Checkpoint.Path,
			})
			if fullAnalysis {
				tailer.SetFromBeginning(true)
				log.Info().Msg("Full analysis mode: reading from beginning")
			}
			reader = tailer
		}
	}

	detectors, cleanupDetectors, detectorStats, err := configuredDetectors(ctx, cfg)
	if err != nil {
		return err
	}
	defer cleanupDetectors()

	var alerters []ports.Alerter
	memAlerter := output.NewMemoryAlerter(100)
	alerters = append(alerters, memAlerter)
	defer func() {
		closeAlerters(alerters)
	}()

	if jsonOut || cfg.Output.JSON.Enabled {
		jsonConfig := output.JSONAlerterConfig{
			Stdout:        cfg.Output.JSON.Stdout || jsonOut,
			Pretty:        true,
			Redact:        cfg.Output.JSON.RedactSensitive,
			IncludeRawLog: cfg.Output.JSON.IncludeRawLog,
			MaxAlertBytes: cfg.Output.JSON.MaxAlertBytes,
		}
		if path := cfg.Output.JSON.Path; path != "" && !jsonOut {
			jsonConfig.FilePath = path
			jsonConfig.Stdout = false
		}
		jsonAlerter, err := output.NewJSONAlerter(jsonConfig)
		if err != nil {
			return fmt.Errorf("failed to create JSON alerter: %w", err)
		}
		var jsonOutput ports.Alerter = jsonAlerter
		if cfg.Output.Dedup.Enabled {
			jsonOutput = output.NewDeduplicatingAlerter(jsonAlerter, output.DedupConfig{
				Enabled: true,
				Window:  time.Duration(cfg.Output.Dedup.WindowSeconds) * time.Second,
			})
		}
		alerters = append(alerters, jsonOutput)
	}

	analyzer := app.NewAnalyzer(reader, detectors, alerters)

	workerConfig := app.WorkerPoolConfig{
		WorkerCount:    cfg.Workers.Count,
		BufferSize:     cfg.Workers.BufferSize,
		SubmitTimeout:  time.Duration(cfg.Workers.SubmitTimeout) * time.Millisecond,
		OverflowPath:   cfg.Workers.OverflowPath,
		QuarantinePath: cfg.Workers.QuarantinePath,
	}
	allowlist, err := app.NewAllowlist(app.AllowlistConfig{
		IPs:             cfg.Detection.Allowlist.IPs,
		CIDRs:           cfg.Detection.Allowlist.CIDRs,
		PathPrefixes:    cfg.Detection.Allowlist.PathPrefixes,
		UserAgentSubstr: cfg.Detection.Allowlist.UserAgentSubstr,
	})
	if err != nil {
		return fmt.Errorf("invalid detection.allowlist: %w", err)
	}
	workerConfig.Allowlist = allowlist
	analyzer.SetWorkerConfig(workerConfig)

	if cfg.Output.Metrics.Enabled {
		promMetrics := output.NewPrometheusMetrics("logradar", analyzer.InternalMetrics())
		promMetrics.SetQueueStatsFunc(analyzer.QueueStats)
		promMetrics.SetThreatIntelStats(
			detectorStats.ThreatIntelEntries,
			detectorStats.ThreatIntelLastReload,
			detectorStats.ThreatIntelFeedErrors,
		)
		promMetrics.SetReadinessCheck(func() (bool, string) {
			if err := analyzer.Err(); err != nil {
				return false, err.Error()
			}
			if analyzer.IsRunning() {
				return true, "analyzer running"
			}
			return false, "analyzer not running"
		})
		analyzer.AddAlertSubscriber(promMetrics)
		analyzer.AddProcessingObserver(promMetrics)

		metricsConfig := output.MetricsConfig{
			Port:       cfg.Output.Metrics.Port,
			Path:       cfg.Output.Metrics.Path,
			HealthPath: "/ready",
			LivePath:   "/live",
		}
		if err := promMetrics.StartServer(metricsConfig); err != nil {
			log.Warn().Err(err).Msg("Failed to start metrics server")
		} else {
			log.Debug().Str("addr", metricsConfig.Port).Msg("Metrics server started")
		}
		defer promMetrics.StopServer()
	}

	if !effectiveTUI {
		log.Info().Msg("Running in console mode")
		analyzer.AddAlertSubscriber(memAlerter)
		err := analyzer.Run(ctx)
		if err != nil {
			return err
		}
		if batchMode {
			if alerts := analyzer.Metrics().TotalAlerts; alerts > 0 {
				return threatsDetectedError{count: alerts}
			}
		}
		return nil
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
	case <-time.After(time.Duration(cfg.App.ShutdownTimeoutSeconds) * time.Second):
		log.Warn().Msg("Shutdown timeout, forcing exit")
	}

	if err := analyzer.Err(); err != nil {
		return err
	}
	return tuiErr
}

func closeAlerters(alerters []ports.Alerter) {
	for i := len(alerters) - 1; i >= 0; i-- {
		alerter := alerters[i]
		if err := alerter.Flush(); err != nil {
			log.Error().Err(err).Msg("Failed to flush alerter")
		}
		if err := alerter.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close alerter")
		}
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if _, ok := err.(threatsDetectedError); ok {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
