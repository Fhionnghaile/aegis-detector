package aegis.detect;

import java.time.Clock;
import java.time.Duration;
import java.nio.file.Path;
import java.util.*;
import org.apache.kafka.clients.consumer.*;
import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.*;

/**
 * Consumes events.raw, evaluates rules, produces to detections.
 * At-least-once: produce the detection(s), THEN commit the offset. A produce failure
 * leaves the offset uncommitted so the event is reprocessed.
 *
 * Built under Maven (kafka-clients). The pure engine is unit-tested with no Kafka.
 */
public final class DetectorApp {
    public static void main(String[] args) throws Exception {
        String brokers = env("AEGIS_KAFKA_BROKERS", "localhost:9092");
        String inTopic = env("AEGIS_IN_TOPIC", "events.raw");
        String outTopic = env("AEGIS_OUT_TOPIC", "detections");
        Path rulesDir = Path.of(env("AEGIS_RULES_DIR", "rules"));

        RuleEngine engine = new RuleEngine(RuleLoader.fromDir(rulesDir), Clock.systemUTC());

        var cprops = new Properties();
        cprops.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, brokers);
        cprops.put(ConsumerConfig.GROUP_ID_CONFIG, "aegis-detector");
        cprops.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false");
        cprops.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        cprops.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        cprops.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);

        var pprops = new Properties();
        pprops.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, brokers);
        pprops.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, "true");
        pprops.put(ProducerConfig.ACKS_CONFIG, "all");
        pprops.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        pprops.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        try (var consumer = new KafkaConsumer<String,String>(cprops);
             var producer = new KafkaProducer<String,String>(pprops)) {
            consumer.subscribe(List.of(inTopic));
            Runtime.getRuntime().addShutdownHook(new Thread(consumer::wakeup));
            while (true) {
                var records = consumer.poll(Duration.ofMillis(500));
                for (var rec : records) {
                    Object event;
                    try { event = Json.parse(rec.value()); }
                    catch (Exception bad) { continue; } // skip unparseable, still commit batch
                    for (Detection d : engine.evaluate(event)) {
                        producer.send(new ProducerRecord<>(outTopic, d.ruleId(), toJson(d))).get();
                    }
                }
                consumer.commitSync(); // only after all detections in the batch are durably produced
            }
        } catch (org.apache.kafka.common.errors.WakeupException ignored) {
            // clean shutdown
        }
    }

    static String toJson(Detection d) {
        StringBuilder b = new StringBuilder("{");
        b.append("\"rule_id\":").append(q(d.ruleId()));
        b.append(",\"title\":").append(q(d.title()));
        b.append(",\"severity\":").append(q(d.severity()));
        b.append(",\"detected_at\":").append(q(d.detectedAt().toString()));
        if (d.groupKey() != null) b.append(",\"group_key\":").append(q(d.groupKey()));
        if (d.count() != null) b.append(",\"count\":").append(d.count());
        return b.append("}").toString();
    }
    private static String q(String s){ return "\"" + s.replace("\\","\\\\").replace("\"","\\\"") + "\""; }
    private static String env(String k, String d){ String v=System.getenv(k); return v==null||v.isEmpty()?d:v; }
}
