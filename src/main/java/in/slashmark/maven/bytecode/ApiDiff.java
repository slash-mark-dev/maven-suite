package in.slashmark.maven.bytecode;

import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Binary API comparison of two versions of a library (JLS chapter 13 rules), and the subset of changes
 * that actually affect a given consumer's bytecode.
 */
public final class ApiDiff {
    private ApiDiff() {}

    /** The public API of one library version. */
    public static final class Api {
        public final Map<String, ClassFile> types = new LinkedHashMap<>();

        public static Api of(Jar jar) {
            Api a = new Api();
            for (ClassFile cf : jar.classes()) {
                if (cf.isModuleInfo()) continue;
                a.types.put(cf.name, cf);
            }
            return a;
        }

        public boolean isExported(ClassFile cf) {
            if (!cf.isPublic() || cf.isSynthetic()) return false;
            // Nested types must also have public enclosing types to be reachable.
            String n = cf.name;
            int d;
            while ((d = n.lastIndexOf('$')) > 0) {
                n = n.substring(0, d);
                ClassFile outer = types.get(n);
                if (outer != null && !outer.isPublic()) return false;
            }
            return true;
        }

        /** Finds a method/field in the type or its supertypes inside this library; null when missing. */
        public ClassFile.Member find(String owner, String name, String desc, boolean field) {
            Set<String> seen = new HashSet<>();
            java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
            q.add(owner);
            while (!q.isEmpty()) {
                String t = q.poll();
                if (!seen.add(t)) continue;
                ClassFile cf = types.get(t);
                if (cf == null) continue;
                for (ClassFile.Member m : field ? cf.fields : cf.methods) {
                    if (m.name.equals(name) && (desc == null || m.descriptor.equals(desc))) return m;
                }
                if (cf.superName != null) q.add(cf.superName);
                q.addAll(cf.interfaces);
            }
            return null;
        }

        /** True when the hierarchy leaves the library (we cannot see members inherited from elsewhere). */
        public boolean hasExternalSuper(String owner) {
            Set<String> seen = new HashSet<>();
            java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
            q.add(owner);
            while (!q.isEmpty()) {
                String t = q.poll();
                if (!seen.add(t)) continue;
                ClassFile cf = types.get(t);
                if (cf == null) {
                    if (!t.equals(owner) && !t.equals("java/lang/Object")) return true;
                    continue;
                }
                if (cf.superName != null) q.add(cf.superName);
                q.addAll(cf.interfaces);
            }
            return false;
        }

        public Set<String> supertypes(String owner) {
            Set<String> out = new LinkedHashSet<>();
            java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
            q.add(owner);
            while (!q.isEmpty()) {
                String t = q.poll();
                ClassFile cf = types.get(t);
                if (cf == null) continue;
                if (cf.superName != null && out.add(cf.superName)) q.add(cf.superName);
                for (String i : cf.interfaces) if (out.add(i)) q.add(i);
            }
            return out;
        }
    }

    public static final class Change implements Json.JsonWritable {
        /** "binary" breaks linking at runtime; "source" breaks compilation or subclasses; "info" is compatible. */
        public final String level;
        public final String kind;
        public final String type;
        public final String member;
        public final String detail;

        Change(String level, String kind, String type, String member, String detail) {
            this.level = level;
            this.kind = kind;
            this.type = type;
            this.member = member;
            this.detail = detail;
        }

        public String typeName() { return type.replace('/', '.'); }

        public String where() {
            return typeName() + (member == null ? "" : "." + member);
        }

        @Override
        public Object toJson() { return Json.obj("level", level, "kind", kind, "type", typeName(), "member", member, "detail", detail); }
    }

    private static String vis(int acc) {
        if ((acc & ClassFile.ACC_PUBLIC) != 0) return "public";
        if ((acc & ClassFile.ACC_PROTECTED) != 0) return "protected";
        if ((acc & ClassFile.ACC_PRIVATE) != 0) return "private";
        return "package-private";
    }

    private static int visRank(int acc) {
        if ((acc & ClassFile.ACC_PUBLIC) != 0) return 3;
        if ((acc & ClassFile.ACC_PROTECTED) != 0) return 2;
        if ((acc & ClassFile.ACC_PRIVATE) != 0) return 0;
        return 1;
    }

    private static String memberName(ClassFile.Member m, boolean field) {
        if (field) {
            int[] end = new int[1];
            return m.name + " : " + ClassFile.typeName(m.descriptor, 0, end);
        }
        int[] end = new int[1];
        String ret = ClassFile.typeName(m.descriptor, m.descriptor.indexOf(')') + 1, end);
        return ClassFile.prettyDescriptor(m.name, m.descriptor) + " : " + ret;
    }

    /** All API changes from old to new. */
    public static List<Change> diff(Api oldApi, Api newApi) {
        List<Change> out = new ArrayList<>();
        for (ClassFile o : oldApi.types.values()) {
            if (!oldApi.isExported(o)) continue;
            ClassFile n = newApi.types.get(o.name);
            if (n == null) {
                out.add(new Change("binary", "type-removed", o.name, null, (o.isInterface() ? "interface" : "class") + " removed"));
                continue;
            }
            if (!newApi.isExported(n)) {
                out.add(new Change("binary", "type-hidden", o.name, null, "no longer public"));
                continue;
            }
            if (o.isInterface() != n.isInterface()) {
                out.add(new Change("binary", "type-kind", o.name, null, (o.isInterface() ? "interface" : "class") + " became " + (n.isInterface() ? "an interface" : "a class")));
                continue;
            }
            if (!o.isFinal() && n.isFinal() && !n.isInterface()) out.add(new Change("source", "type-final", o.name, null, "class is now final (subclasses break)"));
            if (!o.isAbstract() && n.isAbstract() && !n.isInterface()) out.add(new Change("binary", "type-abstract", o.name, null, "class is now abstract (cannot be instantiated)"));
            Set<String> oldSupers = oldApi.supertypes(o.name);
            Set<String> newSupers = newApi.supertypes(n.name);
            for (String s : oldSupers) {
                if (s.equals("java/lang/Object")) continue;
                if (!newSupers.contains(s) && !newApi.hasExternalSuper(n.name)) {
                    out.add(new Change("binary", "supertype-removed", o.name, null, "no longer extends/implements " + s.replace('/', '.')));
                }
            }
            for (ClassFile.Member m : o.methods) {
                if (!m.isApi() || m.name.equals("<clinit>")) continue;
                if (o.isFinal() && m.isProtected()) continue;
                ClassFile.Member nm = null;
                for (ClassFile.Member x : n.methods) if (x.name.equals(m.name) && x.descriptor.equals(m.descriptor)) { nm = x; break; }
                if (nm == null) {
                    ClassFile.Member inherited = newApi.find(n.name, m.name, m.descriptor, false);
                    if (inherited != null && (inherited.isPublic() || inherited.isProtected())) continue;
                    if (inherited == null && newApi.hasExternalSuper(n.name) && !m.name.equals("<init>")) continue;
                    out.add(new Change("binary", m.name.equals("<init>") ? "constructor-removed" : "method-removed", o.name, memberName(m, false), "removed"));
                    continue;
                }
                if (visRank(nm.access) < visRank(m.access)) out.add(new Change("binary", "method-visibility", o.name, memberName(m, false), vis(m.access) + " -> " + vis(nm.access)));
                if (m.isStatic() != nm.isStatic()) out.add(new Change("binary", "method-static", o.name, memberName(m, false), nm.isStatic() ? "became static" : "no longer static"));
                if (!m.isFinal() && nm.isFinal() && !o.isFinal()) out.add(new Change("source", "method-final", o.name, memberName(m, false), "now final (overrides break)"));
                if (!m.isAbstract() && nm.isAbstract()) out.add(new Change("source", "method-abstract", o.name, memberName(m, false), "now abstract (implementations must provide it)"));
            }
            // New abstract methods break implementers / subclasses.
            for (ClassFile.Member nm : n.methods) {
                if (!nm.isAbstract() || nm.isSynthetic()) continue;
                boolean existed = false;
                for (ClassFile.Member x : o.methods) if (x.name.equals(nm.name) && x.descriptor.equals(nm.descriptor)) { existed = true; break; }
                if (!existed) out.add(new Change("source", "abstract-method-added", o.name, memberName(nm, false),
                        (n.isInterface() ? "new interface method without a default" : "new abstract method") + " (implementations must add it)"));
            }
            for (ClassFile.Member f : o.fields) {
                if (!f.isApi()) continue;
                ClassFile.Member nf = null;
                for (ClassFile.Member x : n.fields) if (x.name.equals(f.name)) { nf = x; break; }
                if (nf == null) {
                    if (newApi.find(n.name, f.name, f.descriptor, true) != null || newApi.hasExternalSuper(n.name)) continue;
                    out.add(new Change("binary", "field-removed", o.name, memberName(f, true), "removed"));
                    continue;
                }
                if (!nf.descriptor.equals(f.descriptor)) out.add(new Change("binary", "field-type", o.name, memberName(f, true), "type changed to " + memberName(nf, true)));
                if (visRank(nf.access) < visRank(f.access)) out.add(new Change("binary", "field-visibility", o.name, memberName(f, true), vis(f.access) + " -> " + vis(nf.access)));
                if (f.isStatic() != nf.isStatic()) out.add(new Change("binary", "field-static", o.name, memberName(f, true), nf.isStatic() ? "became static" : "no longer static"));
                if (!f.isFinal() && nf.isFinal()) out.add(new Change("binary", "field-final", o.name, memberName(f, true), "now final (writes fail)"));
            }
        }
        for (ClassFile n : newApi.types.values()) {
            if (newApi.isExported(n) && !oldApi.types.containsKey(n.name)) out.add(new Change("info", "type-added", n.name, null, "new " + (n.isInterface() ? "interface" : "class")));
        }
        return out;
    }

    // ---------------------------------------------------------------- consumer usage

    /** What a consumer's bytecode uses from libraries. */
    public static final class Usage {
        /** owner#name(desc) or owner#name:desc -> classes of the consumer using it. */
        public final Map<String, Set<String>> members = new LinkedHashMap<>();
        public final Map<String, Set<String>> types = new LinkedHashMap<>();
        /** Library types the consumer extends or implements -> consumer classes. */
        public final Map<String, Set<String>> extended = new LinkedHashMap<>();
        /** Consumer methods by class: used to detect overrides of now-final methods. */
        public final Map<String, Set<String>> declaredMethods = new LinkedHashMap<>();
        public int classCount;

        public static Usage of(List<Jar> consumer) {
            Usage u = new Usage();
            for (Jar j : consumer) {
                for (ClassFile cf : j.classes()) {
                    u.classCount++;
                    String me = cf.className();
                    for (ClassFile.Ref r : cf.references) u.members.computeIfAbsent(r.key(), k -> new LinkedHashSet<>()).add(me);
                    for (String t : cf.referencedClasses) u.types.computeIfAbsent(t, k -> new LinkedHashSet<>()).add(me);
                    if (cf.superName != null) u.extended.computeIfAbsent(cf.superName, k -> new LinkedHashSet<>()).add(me);
                    for (String i : cf.interfaces) u.extended.computeIfAbsent(i, k -> new LinkedHashSet<>()).add(me);
                    Set<String> ms = u.declaredMethods.computeIfAbsent(cf.name, k -> new LinkedHashSet<>());
                    for (ClassFile.Member m : cf.methods) ms.add(m.name + m.descriptor);
                }
            }
            return u;
        }

        public boolean usesType(String internalName) { return types.containsKey(internalName) || extended.containsKey(internalName); }
    }

    /** A breaking change together with the consumer classes it hits. */
    public static final class Impact implements Json.JsonWritable {
        public final Change change;
        public final Set<String> usedBy;

        Impact(Change c, Set<String> u) {
            change = c;
            usedBy = u;
        }

        @Override
        public Object toJson() {
            Map<String, Object> m = Json.obj("level", change.level, "kind", change.kind, "type", change.typeName(), "member", change.member, "detail", change.detail);
            m.put("usedBy", new ArrayList<>(usedBy));
            return m;
        }
    }

    /**
     * Which changes the consumer actually hits: removed or changed members it calls, removed types it
     * names, and hierarchy changes in types it extends. Member references are matched through the old
     * hierarchy (a call on a subclass to an inherited method counts).
     */
    public static List<Impact> impacts(List<Change> changes, Api oldApi, Usage usage) {
        List<Impact> out = new ArrayList<>();
        // Index consumer member references by (declaring type in old API, name+desc).
        Map<String, Set<String>> byDeclared = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : usage.members.entrySet()) {
            String key = e.getKey();
            int hash = key.indexOf('#');
            String owner = key.substring(0, hash);
            String rest = key.substring(hash + 1);
            boolean field = rest.contains(":");
            String name = field ? rest.substring(0, rest.indexOf(':')) : rest.substring(0, rest.indexOf('('));
            String desc = field ? rest.substring(rest.indexOf(':') + 1) : rest.substring(rest.indexOf('('));
            String declaring = owner;
            if (oldApi.types.containsKey(owner)) {
                // Walk up to find where the member was declared in the old version.
                java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
                Set<String> seen = new HashSet<>();
                q.add(owner);
                outer:
                while (!q.isEmpty()) {
                    String t = q.poll();
                    if (!seen.add(t)) continue;
                    ClassFile cf = oldApi.types.get(t);
                    if (cf == null) continue;
                    for (ClassFile.Member m : field ? cf.fields : cf.methods) {
                        if (m.name.equals(name) && m.descriptor.equals(desc)) {
                            declaring = t;
                            break outer;
                        }
                    }
                    if (cf.superName != null) q.add(cf.superName);
                    q.addAll(cf.interfaces);
                }
            }
            byDeclared.computeIfAbsent(declaring + "#" + name + (field ? ":" : "") + desc, k -> new LinkedHashSet<>()).addAll(e.getValue());
            if (!declaring.equals(owner)) byDeclared.computeIfAbsent(owner + "#" + name + (field ? ":" : "") + desc, k -> new LinkedHashSet<>()).addAll(e.getValue());
        }
        for (Change c : changes) {
            if ("info".equals(c.level)) continue;
            Set<String> hit = new LinkedHashSet<>();
            switch (c.kind) {
                case "type-removed": case "type-hidden": case "type-kind":
                    Set<String> t = usage.types.get(c.type);
                    if (t != null) hit.addAll(t);
                    Set<String> ex = usage.extended.get(c.type);
                    if (ex != null) hit.addAll(ex);
                    break;
                case "type-final": case "type-abstract": case "supertype-removed": case "abstract-method-added":
                    Set<String> ext = usage.extended.get(c.type);
                    if (ext != null) hit.addAll(ext);
                    if (c.kind.equals("type-abstract")) {
                        Set<String> ctor = byDeclaredStartsWith(byDeclared, c.type + "#<init>(");
                        hit.addAll(ctor);
                    }
                    break;
                default: {
                    ClassFile oc = oldApi.types.get(c.type);
                    if (oc == null || c.member == null) break;
                    boolean field = c.kind.startsWith("field");
                    for (ClassFile.Member m : field ? oc.fields : oc.methods) {
                        if (!memberName(m, field).equals(c.member)) continue;
                        Set<String> users = byDeclared.get(c.type + "#" + m.name + (field ? ":" : "") + m.descriptor);
                        if (users != null) hit.addAll(users);
                        if (c.kind.equals("method-final")) {
                            Set<String> subs = usage.extended.get(c.type);
                            if (subs != null) for (String sub : subs) {
                                Set<String> dm = usage.declaredMethods.get(sub.replace('.', '/'));
                                if (dm != null && dm.contains(m.name + m.descriptor)) hit.add(sub);
                            }
                        }
                    }
                }
            }
            if (!hit.isEmpty()) out.add(new Impact(c, hit));
        }
        return out;
    }

    private static Set<String> byDeclaredStartsWith(Map<String, Set<String>> m, String prefix) {
        Set<String> s = new LinkedHashSet<>();
        for (Map.Entry<String, Set<String>> e : m.entrySet()) if (e.getKey().startsWith(prefix)) s.addAll(e.getValue());
        return s;
    }
}
