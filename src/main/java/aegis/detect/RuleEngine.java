package aegis.detect;

import java.time.*;
import java.util.*;

/** Evaluates all rules against each event. Threshold rules keep bounded per-key sliding windows. */
public final class RuleEngine {
    private final List<Rule> rules; private final Clock clock;
    private final Map<String, Map<String, Deque<Long>>> windows = new HashMap<>();   // ruleId -> key -> timestamps
    private final Map<String, Map<String, Long>> cooldownUntil = new HashMap<>();     // ruleId -> key -> epochMs

    public RuleEngine(List<Rule> rules, Clock clock){ this.rules=rules; this.clock=clock;
        for(Rule r: rules){ windows.put(r.id(), new HashMap<>()); cooldownUntil.put(r.id(), new HashMap<>()); } }

    public List<Detection> evaluate(Object event){
        long now=clock.instant().toEpochMilli();
        List<Detection> out=new ArrayList<>();
        for(Rule r: rules){
            if(!r.when().test(event)) continue;
            if(!r.isThreshold()){
                out.add(new Detection(r.id(), r.title(), r.severity(), Instant.ofEpochMilli(now), null, null, event));
                continue;
            }
            Rule.Threshold t=r.threshold();
            String key=groupKey(event, t.groupBy());
            Map<String,Long> cd=cooldownUntil.get(r.id());
            Long until=cd.get(key);
            if(until!=null && now<until) continue;                 // in cooldown: don't re-fire
            Deque<Long> win=windows.get(r.id()).computeIfAbsent(key, k->new ArrayDeque<>());
            long cutoff=now - t.withinMillis();
            while(!win.isEmpty() && win.peekFirst()<=cutoff) win.pollFirst();   // evict old
            win.addLast(now);
            if(win.size()>=t.count()){
                out.add(new Detection(r.id(), r.title(), r.severity(), Instant.ofEpochMilli(now), key, win.size(), event));
                win.clear(); cd.put(key, now + t.withinMillis());  // cooldown one window
            }
        }
        return out;
    }

    /** Lazy sweep: drop empty/expired windows and lapsed cooldowns so memory stays bounded. */
    public int sweep(){
        long now=clock.instant().toEpochMilli(); int removed=0;
        for(Rule r: rules){
            var wmap=windows.get(r.id()); var cd=cooldownUntil.get(r.id());
            for(var it=wmap.entrySet().iterator(); it.hasNext();){
                var e=it.next(); Deque<Long> w=e.getValue();
                while(!w.isEmpty() && w.peekFirst()<= now - r.threshold().withinMillis()) w.pollFirst();
                Long u=cd.get(e.getKey());
                if(w.isEmpty() && (u==null || now>=u)){ it.remove(); cd.remove(e.getKey()); removed++; }
            }
        }
        return removed;
    }

    private static String groupKey(Object ev, List<String> paths){
        if(paths.isEmpty()) return "";
        StringJoiner j=new StringJoiner("|");
        for(String p: paths) j.add(String.valueOf(Json.path(ev, p)));
        return j.toString();
    }
}
