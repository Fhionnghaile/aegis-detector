package aegis.detect;

import java.util.*;
import java.util.regex.Pattern;

/** A boolean condition over an event (parsed JSON as Map/List/scalar). */
public interface Cond {
    boolean test(Object event);

    static Cond field(String path, String op, Object value){ return new Field(path, op, value); }
    static Cond all(List<Cond> cs){ return ev -> { for(Cond c: cs) if(!c.test(ev)) return false; return true; }; }
    static Cond any(List<Cond> cs){ return ev -> { for(Cond c: cs) if(c.test(ev)) return true; return false; }; }

    final class Field implements Cond {
        final String path, op; final Object value; final Pattern re;
        Field(String p,String o,Object v){ path=p; op=o; value=v; re = "regex".equals(o)? Pattern.compile(String.valueOf(v)) : null; }
        public boolean test(Object ev){
            Object actual = Json.path(ev, path);
            String a = Json.str(actual);
            switch(op){
                case "eq":       return a!=null && a.equals(String.valueOf(value));
                case "contains": return a!=null && a.contains(String.valueOf(value));
                case "regex":    return a!=null && re.matcher(a).find();
                case "in":       return a!=null && ((List<?>)value).stream().map(String::valueOf).anyMatch(a::equals);
                default: throw new IllegalArgumentException("unknown op: "+op);
            }
        }
    }
}
