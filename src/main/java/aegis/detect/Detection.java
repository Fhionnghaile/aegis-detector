package aegis.detect;

import java.time.Instant;

/** A rule match. groupKey/count are null for stateless rules. */
public record Detection(String ruleId, String title, String severity,
                        Instant detectedAt, String groupKey, Integer count, Object event) {}
