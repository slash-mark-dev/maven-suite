package in.slashmark.maven.bytecode;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Reads the parts of a .class file the tools need: version, access flags, type hierarchy, declared
 * members, and every class, method and field the code refers to (from the constant pool).
 */
public final class ClassFile {
    public static final int ACC_PUBLIC = 0x0001, ACC_PRIVATE = 0x0002, ACC_PROTECTED = 0x0004, ACC_STATIC = 0x0008,
            ACC_FINAL = 0x0010, ACC_SYNCHRONIZED = 0x0020, ACC_VOLATILE = 0x0040, ACC_BRIDGE = 0x0040, ACC_VARARGS = 0x0080,
            ACC_NATIVE = 0x0100, ACC_INTERFACE = 0x0200, ACC_ABSTRACT = 0x0400, ACC_SYNTHETIC = 0x1000,
            ACC_ANNOTATION = 0x2000, ACC_ENUM = 0x4000, ACC_MODULE = 0x8000;

    public int minor, major;
    public int access;
    /** Internal name, e.g. com/example/Foo$Bar. */
    public String name;
    public String superName;
    public final List<String> interfaces = new ArrayList<>();
    public final List<Member> fields = new ArrayList<>();
    public final List<Member> methods = new ArrayList<>();
    /** Every class the constant pool mentions (internal names, arrays unwrapped). */
    public final Set<String> referencedClasses = new LinkedHashSet<>();
    /** Every method/field reference: owner, name, descriptor, kind ('M' method, 'F' field, 'I' interface method). */
    public final List<Ref> references = new ArrayList<>();
    /** String constants (used for things like Runtime.exec arguments and URLs). */
    public final List<String> strings = new ArrayList<>();
    public String sourceFile;
    public boolean deprecated;

    public static final class Member {
        public final int access;
        public final String name, descriptor;

        Member(int a, String n, String d) {
            access = a;
            name = n;
            descriptor = d;
        }

        public boolean isPublic() { return (access & ACC_PUBLIC) != 0; }
        public boolean isProtected() { return (access & ACC_PROTECTED) != 0; }
        public boolean isPrivate() { return (access & ACC_PRIVATE) != 0; }
        public boolean isStatic() { return (access & ACC_STATIC) != 0; }
        public boolean isFinal() { return (access & ACC_FINAL) != 0; }
        public boolean isAbstract() { return (access & ACC_ABSTRACT) != 0; }
        public boolean isSynthetic() { return (access & ACC_SYNTHETIC) != 0; }
        public boolean isApi() { return (isPublic() || isProtected()) && !isSynthetic(); }

        @Override
        public String toString() { return name + descriptor; }
    }

    public static final class Ref {
        public final char kind;
        public final String owner, name, descriptor;

        Ref(char k, String o, String n, String d) {
            kind = k;
            owner = o;
            name = n;
            descriptor = d;
        }

        public String key() { return owner + "#" + name + (kind == 'F' ? ":" : "") + descriptor; }
    }

    public boolean isPublic() { return (access & ACC_PUBLIC) != 0; }
    public boolean isInterface() { return (access & ACC_INTERFACE) != 0; }
    public boolean isAbstract() { return (access & ACC_ABSTRACT) != 0; }
    public boolean isFinal() { return (access & ACC_FINAL) != 0; }
    public boolean isSynthetic() { return (access & ACC_SYNTHETIC) != 0; }
    public boolean isModuleInfo() { return (access & ACC_MODULE) != 0 || "module-info".equals(name); }

    /** Dotted name, e.g. com.example.Foo$Bar. */
    public String className() { return name.replace('/', '.'); }

    public String packageName() {
        int i = name.lastIndexOf('/');
        return i < 0 ? "" : name.substring(0, i).replace('/', '.');
    }

    /** Java release for the class file version (52 = 8, 61 = 17, 65 = 21...). */
    public int javaRelease() { return major - 44; }

    public static int javaRelease(int major) { return major - 44; }

    public static ClassFile parse(byte[] data) throws IOException {
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(data));
        if (in.readInt() != 0xCAFEBABE) throw new IOException("not a class file");
        ClassFile cf = new ClassFile();
        cf.minor = in.readUnsignedShort();
        cf.major = in.readUnsignedShort();
        int count = in.readUnsignedShort();
        Object[] pool = new Object[count];
        byte[] tags = new byte[count];
        int[][] refs = new int[count][];
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            tags[i] = (byte) tag;
            switch (tag) {
                case 1: pool[i] = in.readUTF(); break;                 // Utf8
                case 3: case 4: in.readInt(); break;                   // Integer, Float
                case 5: case 6: in.readLong(); i++; break;             // Long, Double (two slots)
                case 7: case 8: case 16: case 19: case 20:             // Class, String, MethodType, Module, Package
                    refs[i] = new int[] {in.readUnsignedShort()};
                    break;
                case 9: case 10: case 11: case 12: case 17: case 18:   // Field/Method/IMethod ref, NameAndType, Dynamic, InvokeDynamic
                    refs[i] = new int[] {in.readUnsignedShort(), in.readUnsignedShort()};
                    break;
                case 15:                                               // MethodHandle
                    in.readUnsignedByte();
                    refs[i] = new int[] {in.readUnsignedShort()};
                    break;
                default: throw new IOException("bad constant pool tag " + tag + " at " + i);
            }
        }
        cf.access = in.readUnsignedShort();
        cf.name = className(pool, refs, in.readUnsignedShort());
        int sup = in.readUnsignedShort();
        cf.superName = sup == 0 ? null : className(pool, refs, sup);
        int ni = in.readUnsignedShort();
        for (int i = 0; i < ni; i++) cf.interfaces.add(className(pool, refs, in.readUnsignedShort()));
        int nf = in.readUnsignedShort();
        for (int i = 0; i < nf; i++) cf.fields.add(member(in, pool, cf));
        int nm = in.readUnsignedShort();
        for (int i = 0; i < nm; i++) cf.methods.add(member(in, pool, cf));
        int na = in.readUnsignedShort();
        for (int i = 0; i < na; i++) {
            String an = (String) pool[in.readUnsignedShort()];
            int len = in.readInt();
            if ("SourceFile".equals(an) && len == 2) {
                cf.sourceFile = (String) pool[in.readUnsignedShort()];
            } else {
                if ("Deprecated".equals(an)) cf.deprecated = true;
                in.skipBytes(len);
            }
        }
        // References from the constant pool.
        for (int i = 1; i < count; i++) {
            switch (tags[i]) {
                case 7: {
                    String cn = (String) pool[refs[i][0]];
                    addClass(cf, cn);
                    break;
                }
                case 8: {
                    Object s = pool[refs[i][0]];
                    if (s instanceof String) cf.strings.add((String) s);
                    break;
                }
                case 9: case 10: case 11: {
                    String owner = (String) pool[refs[refs[i][0]][0]];
                    int[] nat = refs[refs[i][1]];
                    String n = (String) pool[nat[0]], d = (String) pool[nat[1]];
                    char k = tags[i] == 9 ? 'F' : tags[i] == 10 ? 'M' : 'I';
                    if (owner != null && owner.startsWith("[")) owner = arrayElement(owner);
                    if (owner != null) cf.references.add(new Ref(k, owner, n, d));
                    addDescriptorClasses(cf, d);
                    break;
                }
                case 16: {
                    Object d = pool[refs[i][0]];
                    if (d instanceof String) addDescriptorClasses(cf, (String) d);
                    break;
                }
                default: break;
            }
        }
        for (Member f : cf.fields) addDescriptorClasses(cf, f.descriptor);
        for (Member m : cf.methods) addDescriptorClasses(cf, m.descriptor);
        cf.referencedClasses.remove(cf.name);
        return cf;
    }

    private static Member member(DataInputStream in, Object[] pool, ClassFile cf) throws IOException {
        int acc = in.readUnsignedShort();
        String n = (String) pool[in.readUnsignedShort()];
        String d = (String) pool[in.readUnsignedShort()];
        int na = in.readUnsignedShort();
        boolean deprecated = false;
        for (int i = 0; i < na; i++) {
            String an = (String) pool[in.readUnsignedShort()];
            int len = in.readInt();
            if ("Deprecated".equals(an)) deprecated = true;
            in.skipBytes(len);
        }
        return new Member(acc | (deprecated ? 0x100000 : 0), n, d);
    }

    private static String className(Object[] pool, int[][] refs, int idx) {
        if (idx <= 0 || refs[idx] == null) return null;
        Object o = pool[refs[idx][0]];
        return o instanceof String ? (String) o : null;
    }

    private static void addClass(ClassFile cf, String cn) {
        if (cn == null) return;
        if (cn.startsWith("[")) cn = arrayElement(cn);
        if (cn != null) cf.referencedClasses.add(cn);
    }

    static String arrayElement(String desc) {
        int i = 0;
        while (i < desc.length() && desc.charAt(i) == '[') i++;
        if (i < desc.length() && desc.charAt(i) == 'L' && desc.endsWith(";")) return desc.substring(i + 1, desc.length() - 1);
        return null;
    }

    /** Adds the classes named in a field or method descriptor, e.g. (Ljava/lang/String;[Lfoo/Bar;)V. */
    private static void addDescriptorClasses(ClassFile cf, String d) {
        if (d == null) return;
        int i = 0;
        while (i < d.length()) {
            char c = d.charAt(i);
            if (c == 'L') {
                int semi = d.indexOf(';', i);
                if (semi < 0) return;
                cf.referencedClasses.add(d.substring(i + 1, semi));
                i = semi + 1;
            } else i++;
        }
    }

    /** Human readable method signature from a descriptor: (Ljava/lang/String;I)V -> (String, int) */
    public static String prettyDescriptor(String name, String desc) {
        StringBuilder b = new StringBuilder(name).append('(');
        int i = 1;
        boolean first = true;
        while (i < desc.length() && desc.charAt(i) != ')') {
            int[] end = new int[1];
            String t = typeName(desc, i, end);
            if (!first) b.append(", ");
            b.append(t);
            first = false;
            i = end[0];
        }
        b.append(')');
        return b.toString();
    }

    public static String typeName(String desc, int start, int[] end) {
        int dims = 0;
        int i = start;
        while (desc.charAt(i) == '[') { dims++; i++; }
        String t;
        char c = desc.charAt(i);
        switch (c) {
            case 'B': t = "byte"; i++; break;
            case 'C': t = "char"; i++; break;
            case 'D': t = "double"; i++; break;
            case 'F': t = "float"; i++; break;
            case 'I': t = "int"; i++; break;
            case 'J': t = "long"; i++; break;
            case 'S': t = "short"; i++; break;
            case 'Z': t = "boolean"; i++; break;
            case 'V': t = "void"; i++; break;
            case 'L': {
                int semi = desc.indexOf(';', i);
                String full = desc.substring(i + 1, semi).replace('/', '.');
                int dot = full.lastIndexOf('.');
                t = dot >= 0 ? full.substring(dot + 1) : full;
                i = semi + 1;
                break;
            }
            default: t = "?"; i++;
        }
        end[0] = i;
        return t + "[]".repeat(dims);
    }
}
