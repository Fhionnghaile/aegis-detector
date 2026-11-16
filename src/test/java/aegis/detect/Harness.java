package aegis.detect;

import java.time.*;
import java.util.*;

/** Dependency-free verification (run: javac ... && java aegis.detect.Harness). Mirrors the JUnit suite. */
public class Harness {
    static int checks=0, fails=0;
    static void ok(boolean c, String msg){ checks++; if(!c){ fails++; System.out.println("FAIL: "+msg);} }

    static final class TestClock extends Clock {
        Instant t; TestClock(Instant t){ this.t=t; }
        public ZoneId getZone(){ return ZoneOffset.UTC; } public Clock withZone(ZoneId z){ return this; }
        public Instant instant(){ return t; } void advance(long ms){ t=t.plusMillis(ms); }
    }

    static final String S3 = "id: s3-public\ntitle: S3 bucket made public\nseverity: critical\nwhen:\n  all:\n    - { field: type, eq: s3_public }\n";
    static final String BRUTE = "id: auth-bruteforce\ntitle: Repeated failed logins\nseverity: high\nwhen:\n  all:\n    - { field: source, eq: auth }\n    - { field: type,   eq: login_failed }\nthreshold:\n  count: 5\n  within: 60s\n  group_by: [ \"actor.user\" ]\n";

    public static void main(String[] a){
        // YAML loader parses the spec examples
        var rules = RuleLoader.fromStrings(S3, BRUTE);
        ok(rules.size()==2, "load 2 rules");
        ok(rules.get(0).id().equals("s3-public") && !rules.get(0).isThreshold(), "s3 stateless");
        ok(rules.get(1).isThreshold() && rules.get(1).threshold().count()==5 && rules.get(1).threshold().withinMillis()==60000, "brute threshold parsed");

        TestClock clk=new TestClock(Instant.parse("2026-11-14T00:00:00Z"));
        RuleEngine eng=new RuleEngine(rules, clk);

        // stateless match emits once, critical
        var d=eng.evaluate(Json.parse("{\"type\":\"s3_public\",\"source\":\"cloudtrail\"}"));
        ok(d.size()==1 && d.get(0).severity().equals("critical") && d.get(0).count()==null, "stateless emits once");

        // threshold: 4 fails -> nothing; 5th -> fire with count 5
        Object fail = Json.parse("{\"source\":\"auth\",\"type\":\"login_failed\",\"actor\":{\"user\":\"alice\"}}");
        for(int k=0;k<4;k++) ok(eng.evaluate(fail).isEmpty(), "under threshold "+k);
        var fire=eng.evaluate(fail);
        ok(fire.size()==1 && fire.get(0).count()==5 && fire.get(0).groupKey().equals("alice"), "fires at 5");

        // cooldown: immediate next match does NOT re-fire
        ok(eng.evaluate(fail).isEmpty(), "cooldown suppresses re-fire");

        // different user tracked separately (still under threshold)
        Object bob = Json.parse("{\"source\":\"auth\",\"type\":\"login_failed\",\"actor\":{\"user\":\"bob\"}}");
        ok(eng.evaluate(bob).isEmpty(), "bob independent window");

        // after window elapses, cooldown clears and a fresh 5 fires again
        clk.advance(61_000);
        for(int k=0;k<4;k++) eng.evaluate(fail);
        ok(eng.evaluate(fail).size()==1, "re-fires after window");

        // operators: in / contains / regex
        var opRule = RuleLoader.fromStrings("id: r\ntitle: t\nseverity: low\nwhen:\n  any:\n    - { field: type, in: [ a, b ] }\n    - { field: msg, regex: \"deny.*root\" }\n");
        var oe=new RuleEngine(opRule, clk);
        ok(oe.evaluate(Json.parse("{\"type\":\"b\"}")).size()==1, "in operator");
        ok(oe.evaluate(Json.parse("{\"type\":\"z\",\"msg\":\"deny access root\"}")).size()==1, "regex operator");
        ok(oe.evaluate(Json.parse("{\"type\":\"z\",\"msg\":\"allow\"}")).isEmpty(), "no match");

        // sweep bounds memory
        eng.sweep();

        System.out.println(checks+" checks, "+fails+" failures");
        if(fails>0) System.exit(1);
        System.out.println("ALL PASS");
    }
}
