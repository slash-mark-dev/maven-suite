package in.slashmark.maven.util;

import java.io.ByteArrayInputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Safe XML parsing (no DTDs, no external entities) that records the start line of every element,
 * so findings can point at the exact line of a pom.xml.
 */
public final class Xml {
    private Xml() {}

    public static final String LINE = "sm-line";

    public static Element parse(byte[] data) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(false);
            Document doc = dbf.newDocumentBuilder().newDocument();
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setNamespaceAware(false);
            trySet(spf, "http://apache.org/xml/features/disallow-doctype-decl", false);
            trySet(spf, "http://xml.org/sax/features/external-general-entities", false);
            trySet(spf, "http://xml.org/sax/features/external-parameter-entities", false);
            trySet(spf, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            trySet(spf, XMLConstants.FEATURE_SECURE_PROCESSING, true);
            SAXParser parser = spf.newSAXParser();
            Deque<Element> stack = new ArrayDeque<>();
            StringBuilder text = new StringBuilder();
            parser.parse(new InputSource(new ByteArrayInputStream(stripBom(data))), new DefaultHandler() {
                Locator loc;

                @Override
                public void setDocumentLocator(Locator l) { loc = l; }

                @Override
                public void startElement(String uri, String local, String qName, Attributes atts) {
                    flush();
                    String name = qName.contains(":") ? qName.substring(qName.indexOf(':') + 1) : qName;
                    Element e = doc.createElement(name);
                    for (int i = 0; i < atts.getLength(); i++) {
                        String an = atts.getQName(i);
                        if (an.startsWith("xmlns")) continue;
                        try { e.setAttribute(an.contains(":") ? an.substring(an.indexOf(':') + 1) : an, atts.getValue(i)); } catch (RuntimeException ignored) {}
                    }
                    e.setUserData(LINE, loc == null ? 0 : loc.getLineNumber(), null);
                    if (stack.isEmpty()) doc.appendChild(e);
                    else stack.peek().appendChild(e);
                    stack.push(e);
                }

                @Override
                public void endElement(String uri, String local, String qName) {
                    flush();
                    stack.pop();
                }

                @Override
                public void characters(char[] ch, int start, int length) { text.append(ch, start, length); }

                @Override
                public org.xml.sax.InputSource resolveEntity(String publicId, String systemId) {
                    return new InputSource(new ByteArrayInputStream(new byte[0]));
                }

                void flush() {
                    if (text.length() > 0 && !stack.isEmpty()) stack.peek().appendChild(doc.createTextNode(text.toString()));
                    text.setLength(0);
                }
            });
            return doc.getDocumentElement();
        } catch (Exception e) {
            String m = e.getMessage();
            throw new IllegalArgumentException("invalid XML" + (m == null ? "" : ": " + m), e);
        }
    }

    private static byte[] stripBom(byte[] d) {
        if (d.length >= 3 && (d[0] & 0xFF) == 0xEF && (d[1] & 0xFF) == 0xBB && (d[2] & 0xFF) == 0xBF) {
            byte[] o = new byte[d.length - 3];
            System.arraycopy(d, 3, o, 0, o.length);
            return o;
        }
        return d;
    }

    private static void trySet(SAXParserFactory f, String feature, boolean v) {
        try { f.setFeature(feature, v); } catch (Exception ignored) {}
    }

    public static int line(Element e) {
        Object o = e == null ? null : e.getUserData(LINE);
        return o instanceof Integer ? (Integer) o : 0;
    }

    /** First direct child element with the given name, or null. */
    public static Element child(Element parent, String name) {
        if (parent == null) return null;
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element && name.equals(((Element) n).getTagName())) return (Element) n;
        }
        return null;
    }

    /** Direct child elements with the given name (or all children when name is null). */
    public static List<Element> children(Element parent, String name) {
        List<Element> out = new ArrayList<>();
        if (parent == null) return out;
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element && (name == null || name.equals(((Element) n).getTagName()))) out.add((Element) n);
        }
        return out;
    }

    /** Follows a path of child names: path(project, "build", "plugins") -> children named "plugin". */
    public static Element path(Element e, String... names) {
        Element cur = e;
        for (String n : names) {
            cur = child(cur, n);
            if (cur == null) return null;
        }
        return cur;
    }

    /** Trimmed text of a direct child, or null when absent/empty. */
    public static String text(Element parent, String name) {
        Element c = child(parent, name);
        if (c == null) return null;
        String t = c.getTextContent();
        if (t == null) return null;
        t = t.trim();
        return t.isEmpty() ? null : t;
    }

    public static String text(Element e) {
        if (e == null) return null;
        String t = e.getTextContent();
        return t == null || t.trim().isEmpty() ? null : t.trim();
    }

    public static String escape(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '&': b.append("&amp;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&#39;"); break;
                default: b.append(c);
            }
        }
        return b.toString();
    }
}
