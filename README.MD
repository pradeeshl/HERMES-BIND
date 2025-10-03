**HERMES BIND**

A Go-based research tool that simulates and analyzes LDAP injection behavior to learn attack mechanics and improve defensive controls.

**Overview**

Hermes Bind is a Go project created to study LDAP injection behavior in a safe, controlled lab. It simulates LDAP query inputs, inspects server responses, and helps researchers understand how different inputs affect LDAP backends — informing better detection and hardening.

**Purpose**

Learn how LDAP injection vectors behave in practice.

Validate and harden input validation and filtering strategies.

Produce defensive insights (signatures, detection heuristics, test cases) rather than offensive tooling.

**Features**

High-level payload simulator (non-destructive, for lab use only)

Request/response parsing to observe LDAP backend behavior

Logging of simulated queries and parsed responses for analysis

Test harness for reproducing edge cases in a safe environment

“Safe mode” that prevents any live exploitation — lab-only operation

Exportable CSV/JSON results for sharing findings with defenders

**Installation & Usage**

Clone & build:

git clone <repo-url>
cd HERMES_BIND
go build ./...

Run only in an isolated lab environment (no production systems):

./hermes_bind --config test-lab.yaml

Inspect logs/results in results/ (CSV/JSON) for analysis.

Important: Hermes Bind is intended for controlled research and defensive testing. Do not run against systems you do not own or have explicit permission to test.

**Technical Details**

Language: Go

Architecture: Modular simulator + parser + result exporter

Components: input simulator, network/request handler (lab-only), response parser, results exporter

Output Formats: JSON, CSV, human-readable logs

**Security & Ethics**

Lab-only: Run Hermes Bind only on isolated testbeds or authorized targets.

No destructive behavior: Built-in safe-mode prevents live exploitation.

Responsible disclosure: Use findings to improve defenses; follow legal and ethical guidelines.

Include a clear license and acceptable-use statement before publishing.

**Example Output**

[INFO] Starting Hermes Bind (lab mode)  
[TEST] Simulated input #23 — server returned LDAP result set (no injection executed)  
[ANALYSIS] Pattern A: response time spike observed — possible filtering anomaly  
[RESULT] Exported results/analysis_20251003_1012.json  