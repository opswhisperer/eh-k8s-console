// Command eh-k8s-console is a web console for the ExtraHop Kubernetes integration: settings
// editor, validator, sensor-certificate manager, log viewer and alert source.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/term"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/opswhisperer/eh-k8s-console/internal/alerts"
	"github.com/opswhisperer/eh-k8s-console/internal/apply"
	"github.com/opswhisperer/eh-k8s-console/internal/auth"
	"github.com/opswhisperer/eh-k8s-console/internal/certs"
	"github.com/opswhisperer/eh-k8s-console/internal/config"
	"github.com/opswhisperer/eh-k8s-console/internal/discovery"
	"github.com/opswhisperer/eh-k8s-console/internal/finding"
	"github.com/opswhisperer/eh-k8s-console/internal/ignore"
	"github.com/opswhisperer/eh-k8s-console/internal/logs"
	"github.com/opswhisperer/eh-k8s-console/internal/server"
	"github.com/opswhisperer/eh-k8s-console/web"
)

var version = "dev"

const usage = `eh-k8s-console — web console for the ExtraHop Kubernetes integration

Usage:
  eh-k8s-console serve        [-config file] [-read-only] [-insecure-no-auth]
  eh-k8s-console validate     [-config file] [-json] [-exit-code]
  eh-k8s-console certs check  [-config file] [-json] [-exit-code]
  eh-k8s-console hash-password            (reads the password from stdin)
  eh-k8s-console new-api-key  [-name ci] [-role viewer]
  eh-k8s-console version

-exit-code: exit 0 when clean or info only, 1 on warnings, 2 on critical findings.
Kubernetes access: in-cluster service account, else KUBECONFIG/~/.kube/config (-context to pick one).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "validate":
		err = check(os.Args[2:], false)
	case "certs":
		if len(os.Args) < 3 || os.Args[2] != "check" {
			err = errors.New("usage: eh-k8s-console certs check")
			break
		}
		err = check(os.Args[3:], true)
	case "hash-password":
		err = hashPassword()
	case "new-api-key":
		err = newAPIKey(os.Args[2:])
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		err = fmt.Errorf("unknown command %q\n\n%s", os.Args[1], usage)
	}
	var ec exitCode
	if errors.As(err, &ec) {
		os.Exit(int(ec))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type common struct {
	fs         *flag.FlagSet
	configPath *string
	kubeconfig *string
	context    *string
}

func newFlags(name string) common {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return common{fs, fs.String("config", os.Getenv("EHK_CONFIG"), "config file (YAML)"),
		fs.String("kubeconfig", "", "kubeconfig path (default: in-cluster, then KUBECONFIG/~/.kube/config)"),
		fs.String("context", "", "kubeconfig context")}
}

func (c common) load() (*config.Config, error) {
	cfg, err := config.Load(*c.configPath)
	if err != nil {
		return nil, err
	}
	if *c.kubeconfig != "" {
		cfg.Kube.Kubeconfig = *c.kubeconfig
	}
	if *c.context != "" {
		cfg.Kube.Context = *c.context
	}
	return cfg, nil
}

func restConfig(cfg *config.Config) (*rest.Config, error) {
	if cfg.Kube.Kubeconfig == "" && cfg.Kube.Context == "" {
		if rc, err := rest.InClusterConfig(); err == nil {
			return rc, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.Kube.Kubeconfig != "" {
		rules.ExplicitPath = cfg.Kube.Kubeconfig
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: cfg.Kube.Context}).ClientConfig()
}

func clients(cfg *config.Config) (discovery.Clients, error) {
	rc, err := restConfig(cfg)
	if err != nil {
		return discovery.Clients{}, fmt.Errorf("kubernetes config: %w", err)
	}
	rc.QPS, rc.Burst = 20, 40
	rc.UserAgent = "eh-k8s-console/" + version
	k, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return discovery.Clients{}, err
	}
	d, err := dynamic.NewForConfig(rc)
	if err != nil {
		return discovery.Clients{}, err
	}
	return discovery.Clients{Kube: k, Dynamic: d}, nil
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func build(cfg *config.Config, cl discovery.Clients, log *slog.Logger) (*server.Scanner, *apply.Engine, *logs.Reader, *alerts.Collector) {
	ns := cfg.Integration.Namespace
	eng := &apply.Engine{Kube: cl.Kube, Namespace: ns, Prefix: cfg.Integration.Prefix, HistoryKeep: cfg.History.Keep, Log: log}
	eng.ValidateOpts.Prefix, eng.ValidateOpts.ListSep, eng.ValidateOpts.AnnotationKinds = cfg.Integration.Prefix, cfg.Integration.ListSeparator, cfg.Policy.AnnotationKinds
	rules := ignore.NewStore(cl.Kube, ns, "eh-k8s-console-ignore", cfg.Logs.Ignore, cfg.ReadOnly)
	lr := &logs.Reader{Kube: cl.Kube, Namespace: ns, Ignore: rules}
	col := alerts.NewCollector()
	roots, _ := x509.SystemCertPool()
	sc := &server.Scanner{Cfg: cfg, Clients: cl, Logs: lr, Engine: eng, Collector: col, Log: log, Roots: roots, Ignore: rules}
	return sc, eng, lr, col
}

func isLoopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || ip != nil && ip.IsLoopback()
}

func serve(args []string) error {
	c := newFlags("serve")
	readOnly := c.fs.Bool("read-only", false, "never change the cluster (overrides config)")
	insecure := c.fs.Bool("insecure-no-auth", false, "allow auth mode none on a non-loopback address")
	metricsListen := c.fs.String("metrics-listen", ":9090", "address for /metrics (no auth; keep it off the public gateway); empty disables")
	c.fs.Parse(args)
	cfg, err := c.load()
	if err != nil {
		return err
	}
	if *readOnly {
		cfg.ReadOnly = true
	}
	log := newLogger()
	if cfg.HasMode("none") {
		if !isLoopback(cfg.Listen) && !*insecure {
			return fmt.Errorf("auth mode none on %s would let anyone change the integration; listen on 127.0.0.1, configure auth, or pass -insecure-no-auth", cfg.Listen)
		}
		log.Warn("authentication is OFF (auth.modes: [none])")
	}
	cl, err := clients(cfg)
	if err != nil {
		return err
	}
	a, err := auth.New(cfg, log)
	if err != nil {
		return err
	}
	sc, eng, lr, col := build(cfg, cl, log)
	notifier := &alerts.Notifier{Webhooks: cfg.Alerts.Webhooks, BaseURL: cfg.BaseURL, Log: log,
		Store: &alerts.ConfigMapStore{Kube: cl.Kube, Namespace: cfg.Integration.Namespace, Name: "eh-k8s-console-alerts"}}
	if cfg.ReadOnly {
		notifier.Store = nil // read-only never writes to the cluster
	}
	if cfg.Alerts.Events && !cfg.ReadOnly {
		notifier.Events = &alerts.EventRecorder{Kube: cl.Kube, Namespace: cfg.Integration.Namespace, ConfigMap: cfg.Integration.ConfigMap}
	}
	sc.Notifier = notifier

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The notifier names the cluster from the ConfigMap's clusterName once known.
	go func() {
		for ctx.Err() == nil {
			if st := sc.Latest(); st != nil && st.Snap != nil {
				notifier.Cluster = st.Snap.ConfigData["clusterName"]
				return
			}
			time.Sleep(time.Second)
		}
	}()
	go sc.Run(ctx)

	srv := &server.Server{Cfg: cfg, Auth: a, Scanner: sc, Engine: eng, Logs: lr, Notifier: notifier, Static: web.Static(), Log: log, Version: version}
	httpSrv := &http.Server{Addr: cfg.Listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 2)
	go func() { errc <- httpSrv.ListenAndServe() }()
	var metricsSrv *http.Server
	if *metricsListen != "" {
		reg := prometheus.NewRegistry()
		reg.MustRegister(col, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errc <- metricsSrv.ListenAndServe() }()
	}
	log.Info("eh-k8s-console started", "version", version, "listen", cfg.Listen, "metrics", *metricsListen, "namespace", cfg.Integration.Namespace,
		"auth", cfg.Auth.Modes, "readOnly", cfg.ReadOnly, "annotations", cfg.Integration.Annotations.Enabled, "certAutoSync", cfg.Certs.AutoSync)
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	shut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shut)
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shut)
	}
	return nil
}

// check runs one scan without serving and prints findings (validate) or the cert verdict.
func check(args []string, certsOnly bool) error {
	c := newFlags("check")
	asJSON := c.fs.Bool("json", false, "print JSON")
	exit := c.fs.Bool("exit-code", false, "exit 1 on warnings, 2 on critical findings")
	c.fs.Parse(args)
	cfg, err := c.load()
	if err != nil {
		return err
	}
	cfg.ReadOnly = true // a check never changes anything
	cl, err := clients(cfg)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sc, _, _, _ := build(cfg, cl, log)
	if certsOnly {
		sc.Logs, sc.SkipNetwork = nil, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	st := sc.Scan(ctx)
	fs := st.Findings
	if certsOnly {
		fs = nil
		if st.Certs != nil {
			fs = st.Certs.Findings
		}
	}
	if *asJSON {
		out := map[string]any{"findings": fs}
		if certsOnly {
			out["certs"] = st.Certs
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
	} else {
		if certsOnly && st.Certs != nil {
			printCerts(st.Certs)
		}
		if len(fs) == 0 {
			fmt.Println("No findings.")
		}
		for _, f := range fs {
			fmt.Printf("%-8s %-8s %-28s %s\n", strings.ToUpper(string(f.Severity)), f.Source, f.Code, f.Message)
			if f.Fix != "" && f.Severity != finding.Info {
				fmt.Printf("%47s→ %s\n", "", f.Fix)
			}
		}
	}
	if *exit {
		switch finding.Max(fs) {
		case finding.Critical:
			return exitCode(2)
		case finding.Warning:
			return exitCode(1)
		}
	}
	return nil
}

func printCerts(a *certs.Assessment) {
	fmt.Printf("State: %s — %s\n\n", a.State, a.Summary)
	row := func(src string, c certs.Info) {
		fmt.Printf("  %-6s %-12s %-50.50s %s  expires %s (%dd)\n", src, c.Role, c.Subject, certs.ShortFP(c.SHA256), c.NotAfter.Format("2006-01-02"), c.DaysLeft)
	}
	fmt.Println("sensorCert bundle:")
	for _, c := range a.Bundle {
		row("bundle", c)
	}
	if a.Probe != nil && a.Probe.Error == "" {
		fmt.Printf("\nSensor %s (SNI %s) presents:\n", a.Probe.Addr, a.Probe.ServerName)
		for _, c := range a.Probe.Chain {
			row("live", c)
		}
	}
	fmt.Printf("\ntrusted by bundle: %v   public CA: %v   name matches: %v   leaf changed: %v\n", a.TrustedByBundle, a.PublicCA, a.SNIMatches, a.LeafChanged)
	if a.Anchor != nil {
		fmt.Printf("trust anchor in bundle: %s (%s, expires %s)\n", a.Anchor.Subject, certs.ShortFP(a.Anchor.SHA256), a.Anchor.NotAfter.Format("2006-01-02"))
	}
	fmt.Println()
}

func hashPassword() error {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pw = string(b)
	} else {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		if err != nil {
			return err
		}
		pw = strings.TrimRight(string(b), "\r\n")
	}
	if len(pw) < 12 {
		return errors.New("use at least 12 characters")
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

func newAPIKey(args []string) error {
	fs := flag.NewFlagSet("new-api-key", flag.ExitOnError)
	name := fs.String("name", "automation", "key name (shown in audit logs)")
	role := fs.String("role", auth.Viewer, "viewer, operator or admin")
	fs.Parse(args)
	if auth.Rank(*role) == 0 {
		return fmt.Errorf("unknown role %q", *role)
	}
	key, hash := auth.NewAPIKey()
	// stdout: the key alone. stderr: valid YAML (notes are comments), so `2>> api-keys.yaml` works.
	fmt.Println(key)
	fmt.Fprintf(os.Stderr, "# API key %q: the key was printed on stdout once; store it in your secret manager.\n- name: %s\n  hash: %s\n  role: %s\n", *name, *name, hash, *role)
	return nil
}
