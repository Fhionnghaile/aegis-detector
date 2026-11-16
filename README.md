# Aegis Detection Consumer (Java)

<!-- at-a-glance -->
> **A streaming detection consumer that turns a firehose of events into scored alerts.**  
> **Result:** 3 JUnit suites; table-driven detection logic.  
> **Reproduce:** `mvn test   # (or ./gradlew test)`  
> ![CI](https://github.com/fhionnghaile/aegis-detector/actions/workflows/ci.yml/badge.svg)
>
> **What this is worth:** Where raw telemetry becomes 'something is wrong' — the signal a SOC actually acts on.


The second Aegis service: consume `events.raw` from Kafka, evaluate **Sigma-style detection rules**
in real time, publish matches to `detections`. At-least-once (produce, then commit).

## Rule model (Sigma-lite YAML, `rules/*.yml`)
- **stateless** — match a single event.
- **threshold** — N matches within a sliding window, grouped by a key, with cooldown + eviction.
- operators `eq` / `in` / `contains` / `regex`; combinators `all` / `any` (nestable); dotted field paths.

```yaml
id: auth-bruteforce
severity: high
when:
  all:
    - { field: source, eq: auth }
    - { field: type,   eq: login_failed }
threshold: { count: 5, within: 60s, group_by: [ "actor.user" ] }
```

## The engine is dependency-free and fully tested
`src/main/java/aegis/detect` parses JSON and the rule YAML with zero third-party libraries, so the
detection logic compiles and runs anywhere:
```bash
javac -d build $(find src/main src/test -name "*.java" ! -name DetectorApp.java ! -name RuleEngineTest.java)
java -cp build aegis.detect.Harness     # 15 checks, ALL PASS
```
Full build + JUnit 5 + the Kafka consumer:
```bash
mvn test            # runs RuleEngineTest
mvn -q package      # builds the DetectorApp consumer (kafka-clients)
```

## Threshold semantics (exact)
Per `group_key`: keep timestamps within `within`; on each match drop expired, append now; when
`size >= count` emit `Detection{count, groupKey}`, then **cooldown** for one window (no per-event
re-fire); a `sweep()` evicts empty/expired windows so memory stays bounded.

## Run with the gateway
`events.raw` is produced by **01 Gateway (Go)**. `docker compose up` in the Aegis root wires
gateway → Redpanda → this consumer → `detections` (dashboarded by 03).

## License
MIT.

## Key decisions

- JVM for a mature streaming ecosystem and strong typing on the detection rules.
- Detection logic is table-driven and unit-tested, so a new rule is data + a test, not a rewrite.
- Separated from ingest (the gateway) so each scales and fails independently.

## Scope & limits

- Reference detections, not a full ATT&CK-mapped catalogue — the framework is the contribution.
- Thresholds and false-positive rates are environment-specific and need tuning.

