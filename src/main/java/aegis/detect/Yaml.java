package aegis.detect;

import java.util.*;

/** Tiny YAML subset for Sigma-lite rules: block maps, block/flow sequences, flow maps, scalars. */
public final class Yaml {
    private final List<String> lines; private int idx;
    private Yaml(List<String> l){ this.lines=l; }

    public static Object parse(String text){
        List<String> ls=new ArrayList<>();
        for(String raw: text.split("\n",-1)){
            String noComment = stripComment(raw);
            if(noComment.strip().isEmpty()) continue;
            ls.add(noComment);
        }
        return new Yaml(ls).block(indentOf(ls.get(0)));
    }
    private static String stripComment(String s){
        boolean inq=false;
        for(int k=0;k<s.length();k++){ char c=s.charAt(k); if(c=='"') inq=!inq; else if(c=='#'&&!inq) return s.substring(0,k); }
        return s;
    }
    private static int indentOf(String s){ int n=0; while(n<s.length()&&s.charAt(n)==' ') n++; return n; }

    private Object block(int indent){
        String first=lines.get(idx).substring(indent);
        if(first.startsWith("- ")) return seq(indent);
        return map(indent);
    }
    private Map<String,Object> map(int indent){
        Map<String,Object> m=new LinkedHashMap<>();
        while(idx<lines.size()){
            String line=lines.get(idx); int ind=indentOf(line);
            if(ind<indent) break; if(ind>indent) throw new IllegalArgumentException("bad indent: "+line);
            String body=line.substring(indent); int colon=findColon(body);
            if(colon<0) throw new IllegalArgumentException("expected key: "+line);
            String key=body.substring(0,colon).strip();
            String rest=body.substring(colon+1).strip();
            idx++;
            if(!rest.isEmpty()){ m.put(key, scalarOrFlow(rest)); }
            else {
                if(idx<lines.size() && indentOf(lines.get(idx))>indent) m.put(key, block(indentOf(lines.get(idx))));
                else m.put(key, null);
            }
        }
        return m;
    }
    private List<Object> seq(int indent){
        List<Object> a=new ArrayList<>();
        while(idx<lines.size()){
            String line=lines.get(idx); int ind=indentOf(line);
            if(ind<indent || !line.substring(indent).startsWith("- ")) break;
            String item=line.substring(indent+2).strip();
            idx++;
            a.add(scalarOrFlow(item));
        }
        return a;
    }
    private static int findColon(String s){ boolean inq=false,inb=false;
        for(int k=0;k<s.length();k++){ char c=s.charAt(k); if(c=='"')inq=!inq; else if(c=='{'||c=='[')inb=true;
            else if(c=='}'||c==']')inb=false; else if(c==':'&&!inq&&!inb) return k; } return -1; }

    private static Object scalarOrFlow(String s){
        s=s.strip();
        if(s.startsWith("{")) return flowMap(s);
        if(s.startsWith("[")) return flowSeq(s);
        return scalar(s);
    }
    private static Object scalar(String s){
        if(s.length()>=2 && s.startsWith("\"") && s.endsWith("\"")) return s.substring(1,s.length()-1);
        return s; // keep as string; callers coerce (ints, durations)
    }
    private static Map<String,Object> flowMap(String s){
        Map<String,Object> m=new LinkedHashMap<>();
        for(String part: splitTop(s.substring(1,s.length()-1))){
            int c=part.indexOf(':'); m.put(part.substring(0,c).strip(), scalarOrFlow(part.substring(c+1).strip()));
        }
        return m;
    }
    private static List<Object> flowSeq(String s){
        List<Object> a=new ArrayList<>();
        String inner=s.substring(1,s.length()-1).strip();
        if(inner.isEmpty()) return a;
        for(String part: splitTop(inner)) a.add(scalar(part.strip()));
        return a;
    }
    private static List<String> splitTop(String s){
        List<String> out=new ArrayList<>(); int depth=0; boolean inq=false; StringBuilder b=new StringBuilder();
        for(int k=0;k<s.length();k++){ char c=s.charAt(k);
            if(c=='"') inq=!inq;
            if(!inq&&(c=='{'||c=='[')) depth++;
            if(!inq&&(c=='}'||c==']')) depth--;
            if(c==','&&depth==0&&!inq){ out.add(b.toString()); b.setLength(0);} else b.append(c);
        }
        if(b.length()>0) out.add(b.toString());
        return out;
    }
}
