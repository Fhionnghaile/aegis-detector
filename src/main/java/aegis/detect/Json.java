package aegis.detect;

import java.util.*;

/** Minimal dependency-free JSON: parse to Map/List/String/Double/Boolean/null, dotted-path access. */
public final class Json {
    private final String s; private int i;
    private Json(String s){ this.s=s; }

    public static Object parse(String s){ Json p=new Json(s); p.ws(); Object v=p.value(); p.ws();
        if(p.i!=s.length()) throw new IllegalArgumentException("trailing JSON"); return v; }

    /** Navigate a dotted path (e.g. "actor.user"); returns null if absent. */
    @SuppressWarnings("unchecked")
    public static Object path(Object node, String dotted){
        Object cur=node;
        for(String part: dotted.split("\\.")){
            if(!(cur instanceof Map<?,?> m)) return null;
            cur=((Map<String,Object>)m).get(part);
            if(cur==null) return null;
        }
        return cur;
    }
    public static String str(Object o){ return o==null?null:String.valueOf(o); }

    private void ws(){ while(i<s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private Object value(){
        char c=s.charAt(i);
        switch(c){
            case '{': return obj();
            case '[': return arr();
            case '"': return string();
            case 't': expect("true"); return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null"); return null;
            default: return number();
        }
    }
    private Map<String,Object> obj(){ Map<String,Object> m=new LinkedHashMap<>(); i++; ws();
        if(s.charAt(i)=='}'){ i++; return m; }
        while(true){ ws(); String k=string(); ws(); if(s.charAt(i++)!=':') throw err(); ws();
            m.put(k, value()); ws(); char c=s.charAt(i++); if(c=='}') return m; if(c!=',') throw err(); }
    }
    private List<Object> arr(){ List<Object> a=new ArrayList<>(); i++; ws();
        if(s.charAt(i)==']'){ i++; return a; }
        while(true){ ws(); a.add(value()); ws(); char c=s.charAt(i++); if(c==']') return a; if(c!=',') throw err(); }
    }
    private String string(){ if(s.charAt(i++)!='"') throw err(); StringBuilder b=new StringBuilder();
        while(true){ char c=s.charAt(i++); if(c=='"') return b.toString();
            if(c=='\\'){ char e=s.charAt(i++); switch(e){ case 'n': b.append('\n'); break; case 't': b.append('\t'); break;
                case 'r': b.append('\r'); break; case '"': b.append('"'); break; case '\\': b.append('\\'); break;
                case '/': b.append('/'); break; case 'u': b.append((char)Integer.parseInt(s.substring(i,i+4),16)); i+=4; break;
                default: b.append(e); } } else b.append(c); } }
    private Double number(){ int st=i; while(i<s.length() && "+-0123456789.eE".indexOf(s.charAt(i))>=0) i++;
        return Double.valueOf(s.substring(st,i)); }
    private void expect(String t){ if(!s.startsWith(t,i)) throw err(); i+=t.length(); }
    private IllegalArgumentException err(){ return new IllegalArgumentException("bad JSON at "+i); }
}
