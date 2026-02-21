// Detection service: consumes normalized events, evaluates rules, emits alerts.
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"edr-linux/pkg/detection"
	"edr-linux/pkg/events"
	"edr-linux/pkg/sigma"

	"github.com/nats-io/nats.go"
)

func main() {
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	sigmaDir := getEnv("SIGMA_RULES", "sigma/rules")

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("nats connect: %v", err)
	}
	defer nc.Close()

	eng := detection.NewEngine()
	rules, err := sigma.LoadDir(sigmaDir)
	if err != nil {
		log.Printf("sigma load %s: %v (using built-in fallback)", sigmaDir, err)
		eng.AddRule(detection.Rule{
			ID:       "proc-lnx-netcat-revshell",
			Name:     "Suspicious Netcat Reverse Shell",
			Severity: "high",
			Cond: detection.Condition{
				Op: "or",
				Children: []detection.Condition{
					{
						Op: "and",
						Children: []detection.Condition{
							{Field: "process.command_line", Op: "contains", Value: " -e "},
							{Field: "process.executable", Op: "endswith", Value: "/nc"},
						},
					},
					{
						Op: "and",
						Children: []detection.Condition{
							{Field: "process.command_line", Op: "contains", Value: " -e "},
							{Field: "process.executable", Op: "endswith", Value: "ncat"},
						},
					},
				},
			},
			Mitre: []string{"T1059"},
		})
	} else {
		eng.SetRules(rules)
		log.Printf("sigma: loaded %d rules from %s", len(rules), sigmaDir)
	}

	reloadSub, errReload := nc.Subscribe("detection.reload", func(m *nats.Msg) {
		rules, err := sigma.LoadDir(sigmaDir)
		if err != nil {
			log.Printf("sigma reload: %v", err)
			return
		}
		eng.SetRules(rules)
		log.Printf("sigma: reloaded %d rules", len(rules))
	})
	if errReload != nil {
		log.Printf("detection.reload subscribe: %v", errReload)
	}

	sub, err := nc.Subscribe("events.detection", func(m *nats.Msg) {
		var norm events.NormalizedEvent
		if err := json.Unmarshal(m.Data, &norm); err != nil {
			log.Printf("unmarshal: %v", err)
			return
		}
		matched := eng.Eval(&norm)
		for _, r := range matched {
			raw, _ := json.Marshal(norm)
			var rawMap map[string]interface{}
			_ = json.Unmarshal(raw, &rawMap)
			alert := events.Alert{
				ID:        "alt-" + time.Now().Format("20060102150405"),
				TenantID:  norm.TenantID,
				HostID:    norm.HostID,
				RuleID:    r.ID,
				RuleName:  r.Name,
				Severity:  r.Severity,
				Title:     r.Name,
				Message:   "Rule " + r.ID + " matched",
				EventJSON: rawMap,
				Mitre:     r.Mitre,
				CreatedAt: time.Now(),
			}
			out, _ := json.Marshal(alert)
			nc.Publish("alerts", out)
			log.Printf("alert: %s %s on %s", r.Severity, r.Name, norm.HostID)
		}
	})
	if err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	if reloadSub != nil {
		defer reloadSub.Unsubscribe()
	}

	log.Println("detection: listening on events.detection")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("detection: shutdown")
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
