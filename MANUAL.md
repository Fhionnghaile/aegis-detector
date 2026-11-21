# Aegis Detection Consumer (Java) — manual

*One page, eight blocks. Every figure here comes from this repository's own tests and README.*

## 1. Claim
Sigma-style rules (stateless and windowed threshold) evaluate the event stream with bounded memory. The dependency-free engine passes its 15-check harness.

## 2. What it is
The second Aegis service reads raw events from Kafka, applies detection rules written as YAML, and publishes matches as alerts. A new detection is a rule file plus a test, not new code.

## 3. Demo
Capture to record: the dependency-free harness (`java -cp build aegis.detect.Harness`) printing all checks passing, plus `mvn test`.

## 4. Run it yourself
**Prerequisites:** JDK. Maven for the JUnit suite and the Kafka consumer.

```bash
javac -d build $(find src/main src/test -name "*.java" ! -name DetectorApp.java ! -name RuleEngineTest.java)
java -cp build aegis.detect.Harness
mvn test
```

## 5. What you will see
The harness reports 15 checks, all passing. `mvn test` runs RuleEngineTest green.

## 6. 30-second talking point
> This is where raw telemetry becomes "something is wrong". The rules are data, the threshold windows have exact, tested semantics, and memory stays bounded because expired windows are swept.

## 7. Scope and limits
- Reference detections, not a full ATT&CK-mapped catalogue. The framework is the contribution.
- Thresholds and false-positive rates are environment-specific and need tuning.

## 8. Links
[Repository](https://github.com/fhionnghaile/aegis-detector) · [README](README.md)
