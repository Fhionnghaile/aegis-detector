package aegis.detect;

import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** JUnit 5 suite (mvn test). The same cases run dependency-free in Harness.java. */
class RuleEngineTest {
    static final String S3 = "id: s3-public\ntitle: S3 bucket made public\nseverity: critical\nwhen:\n  all:\n    - { field: type, eq: s3_public }\n";
    static final String BRUTE = "id: auth-bruteforce\ntitle: Repeated failed logins\nseverity: high\nwhen:\n  all:\n    - { field: source, eq: auth }\n    - { field: type, eq: login_failed }\nthreshold:\n  count: 5\n  within: 60s\n  group_by: [ \"actor.user\" ]\n";

    static final class TestClock extends Clock {
        Instant t; TestClock(Instant t){ this.t=t; }
        public ZoneId getZone(){ return ZoneOffset.UTC; } public Clock withZone(ZoneId z){ return this; }
        public Instant instant(){ return t; } void advance(long ms){ t=t.plusMillis(ms); }
    }
    static Object ev(String j){ return Json.parse(j); }

    @Test void stateless_match_emits_once() {
        var e = new RuleEngine(RuleLoader.fromStrings(S3), Clock.systemUTC());
        var d = e.evaluate(ev("{\"type\":\"s3_public\",\"source\":\"cloudtrail\"}"));
        assertEquals(1, d.size());
        assertEquals("critical", d.get(0).severity());
        assertNull(d.get(0).count());
    }

    @Test void threshold_fires_at_count_then_cools_down() {
        var clk = new TestClock(Instant.parse("2026-11-14T00:00:00Z"));
        var e = new RuleEngine(RuleLoader.fromStrings(BRUTE), clk);
        var f = ev("{\"source\":\"auth\",\"type\":\"login_failed\",\"actor\":{\"user\":\"alice\"}}");
        for (int k=0;k<4;k++) assertTrue(e.evaluate(f).isEmpty());
        var fire = e.evaluate(f);
        assertEquals(1, fire.size());
        assertEquals(5, fire.get(0).count());
        assertEquals("alice", fire.get(0).groupKey());
        assertTrue(e.evaluate(f).isEmpty(), "cooldown");
        clk.advance(61_000);
        for (int k=0;k<4;k++) e.evaluate(f);
        assertEquals(1, e.evaluate(f).size(), "re-fires after window");
    }

    @Test void operators_in_and_regex() {
        var e = new RuleEngine(RuleLoader.fromStrings(
            "id: r\ntitle: t\nseverity: low\nwhen:\n  any:\n    - { field: type, in: [ a, b ] }\n    - { field: msg, regex: \"deny.*root\" }\n"),
            Clock.systemUTC());
        assertEquals(1, e.evaluate(ev("{\"type\":\"b\"}")).size());
        assertEquals(1, e.evaluate(ev("{\"type\":\"z\",\"msg\":\"deny access root\"}")).size());
        assertTrue(e.evaluate(ev("{\"type\":\"z\",\"msg\":\"allow\"}")).isEmpty());
    }
}
