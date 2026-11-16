package aegis.detect;

import java.util.*;

/** A parsed rule: a condition, and (optionally) a threshold making it stateful. */
public record Rule(String id, String title, String severity, Cond when, Threshold threshold) {
    public boolean isThreshold(){ return threshold != null; }

    public record Threshold(int count, long withinMillis, List<String> groupBy) {}
}
