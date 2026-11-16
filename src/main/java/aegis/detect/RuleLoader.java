package aegis.detect;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;

/** Parse Sigma-lite YAML (string or rules/*.yml) into Rule objects. */
public final class RuleLoader {

    public static List<Rule> fromStrings(String... yamls){
        List<Rule> rs=new ArrayList<>();
        for(String y: yamls) rs.add(one(Yaml.parse(y)));
        return rs;
    }
    public static List<Rule> fromDir(Path dir) throws IOException {
        try(Stream<Path> s=Files.list(dir)){
            List<Rule> rs=new ArrayList<>();
            for(Path p: s.filter(x->x.toString().endsWith(".yml")||x.toString().endsWith(".yaml")).sorted().toList())
                rs.add(one(Yaml.parse(Files.readString(p))));
            return rs;
        }
    }

    @SuppressWarnings("unchecked")
    private static Rule one(Object parsed){
        Map<String,Object> m=(Map<String,Object>)parsed;
        String id=(String)m.get("id"), title=(String)m.get("title"), sev=(String)m.get("severity");
        Cond when=cond((Map<String,Object>)m.get("when"));
        Rule.Threshold thr=null;
        if(m.get("threshold") instanceof Map<?,?> tm0){
            Map<String,Object> tm=(Map<String,Object>)tm0;
            int count=Integer.parseInt(String.valueOf(tm.get("count")));
            long within=duration(String.valueOf(tm.get("within")));
            List<String> gb=((List<Object>)tm.getOrDefault("group_by", List.of())).stream().map(String::valueOf).toList();
            thr=new Rule.Threshold(count, within, gb);
        }
        return new Rule(id,title,sev,when,thr);
    }
    @SuppressWarnings("unchecked")
    private static Cond cond(Map<String,Object> when){
        if(when.containsKey("all"))
            return Cond.all(((List<Object>)when.get("all")).stream().map(RuleLoader::leaf).toList());
        if(when.containsKey("any"))
            return Cond.any(((List<Object>)when.get("any")).stream().map(RuleLoader::leaf).toList());
        return leaf(when);
    }
    @SuppressWarnings("unchecked")
    private static Cond leaf(Object node){
        Map<String,Object> m=(Map<String,Object>)node;
        if(m.containsKey("all")||m.containsKey("any")) return cond(m);
        String field=(String)m.get("field");
        for(String op: new String[]{"eq","in","contains","regex"})
            if(m.containsKey(op)) return Cond.field(field, op, m.get(op));
        throw new IllegalArgumentException("leaf needs field+op: "+m);
    }
    static long duration(String d){
        d=d.strip();
        char u=d.charAt(d.length()-1);
        long n=Long.parseLong(d.substring(0,d.length()-1));
        return switch(u){ case 's'->n*1000; case 'm'->n*60_000; case 'h'->n*3_600_000; default->Long.parseLong(d); };
    }
}
