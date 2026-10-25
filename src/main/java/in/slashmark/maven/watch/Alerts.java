package in.slashmark.maven.watch;

import in.slashmark.maven.util.Env;
import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Alert delivery for every watch tool: Slack, Microsoft Teams, Discord, generic signed webhooks,
 * e-mail over SMTP and append-only JSON files. Channels live in alerts.json in the config folder;
 * SM_MAVEN_SLACK_WEBHOOK / SM_MAVEN_TEAMS_WEBHOOK / SM_MAVEN_WEBHOOK add channels from the environment
 * (handy in CI secrets).
 */
public final class Alerts {
    public static final List<String> TYPES = List.of("slack", "teams", "discord", "webhook", "email", "file");

    public static final class Channel {
        public String name, type, url, secret, file;
        public String host, user, password, from;
        public int port = 587;
        public String tls = "starttls"; // starttls | ssl | none
        public final List<String> to = new ArrayList<>();
        public String minSeverity;     // only send alerts at or above this level
        public boolean fromEnv;

        public Map<String, Object> toJson(boolean redact) {
            Map<String, Object> m = Json.obj("name", name, "type", type, "url", redact ? redactUrl(url) : url,
                    "secret", secret == null ? null : redact ? "***" : secret, "file", file, "host", host,
                    "port", "email".equals(type) ? port : null, "tls", "email".equals(type) ? tls : null, "user", user,
                    "password", password == null ? null : redact ? "***" : password, "from", from,
                    "to", to.isEmpty() ? null : to, "minSeverity", minSeverity, "source", fromEnv ? "environment" : null);
            return m;
        }

        static String redactUrl(String u) {
            if (u == null) return null;
            // Webhook URLs are secrets: keep scheme + host only.
            try {
                URI x = URI.create(u);
                return x.getScheme() + "://" + x.getHost() + "/…";
            } catch (RuntimeException e) {
                return "***";
            }
        }
    }

    /** One alert: a title, a severity, short lines, and structured data for webhooks. */
    public static final class Alert {
        public String tool, title, severity = "info", link;
        public final List<String> lines = new ArrayList<>();
        public Object data;

        public Alert(String tool, String title) {
            this.tool = tool;
            this.title = title;
        }

        public Alert line(String s) {
            lines.add(s);
            return this;
        }
    }

    private final Path file;
    private final Http http;
    private final Env env;
    private final List<Channel> channels = new ArrayList<>();

    public Alerts(Path configDir, Http http, Env env) throws IOException {
        this.file = configDir.resolve("alerts.json");
        this.http = http;
        this.env = env;
        load();
    }

    public Path file() { return file; }

    public List<Channel> channels() { return channels; }

    private void load() throws IOException {
        channels.clear();
        if (Files.isRegularFile(file)) {
            Object j;
            try {
                j = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                throw new IOException(file + " is not valid JSON: " + e.getMessage());
            }
            for (Object o : Json.list(j, "channels")) {
                Channel c = new Channel();
                c.name = Json.str(o, "name");
                c.type = Json.str(o, "type");
                c.url = Json.str(o, "url");
                c.secret = Json.str(o, "secret");
                c.file = Json.str(o, "file");
                c.host = Json.str(o, "host");
                c.port = (int) Json.num(o, 587, "port");
                c.tls = Json.str(o, "tls") == null ? "starttls" : Json.str(o, "tls");
                c.user = Json.str(o, "user");
                c.password = Json.str(o, "password");
                c.from = Json.str(o, "from");
                c.minSeverity = Json.str(o, "minSeverity");
                for (Object t : Json.list(o, "to")) c.to.add(String.valueOf(t));
                channels.add(c);
            }
        }
        addEnv("slack", env.get("SM_MAVEN_SLACK_WEBHOOK"));
        addEnv("teams", env.get("SM_MAVEN_TEAMS_WEBHOOK"));
        addEnv("discord", env.get("SM_MAVEN_DISCORD_WEBHOOK"));
        addEnv("webhook", env.get("SM_MAVEN_WEBHOOK"));
    }

    private void addEnv(String type, String url) {
        if (url == null) return;
        Channel c = new Channel();
        c.name = type + "-env";
        c.type = type;
        c.url = url;
        c.secret = "webhook".equals(type) ? env.get("SM_MAVEN_WEBHOOK_SECRET") : null;
        c.fromEnv = true;
        channels.add(c);
    }

    public void save() throws IOException {
        List<Object> list = new ArrayList<>();
        for (Channel c : channels) if (!c.fromEnv) list.add(c.toJson(false));
        Files.createDirectories(file.getParent());
        Files.writeString(file, Json.write(Json.obj("channels", list)), StandardCharsets.UTF_8);
        try {
            // The file holds webhook URLs and SMTP passwords: owner-only on POSIX systems.
            Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException ignored) {}
    }

    public Channel find(String name) {
        for (Channel c : channels) if (c.name.equalsIgnoreCase(name)) return c;
        return null;
    }

    /** Result of one delivery attempt. */
    public static final class Delivery {
        public final String channel;
        public final boolean ok;
        public final String error;

        Delivery(String channel, boolean ok, String error) {
            this.channel = channel;
            this.ok = ok;
            this.error = error;
        }
    }

    private static int rank(String sev) {
        switch (sev == null ? "" : sev.toLowerCase(Locale.ROOT)) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    /** Sends an alert to every channel (or the named ones), honouring each channel's minimum severity. */
    public List<Delivery> send(Alert a, List<String> only) {
        List<Delivery> out = new ArrayList<>();
        for (Channel c : channels) {
            if (only != null && !only.isEmpty() && !only.contains(c.name)) continue;
            if (c.minSeverity != null && rank(a.severity) < rank(c.minSeverity)) continue;
            try {
                deliver(c, a);
                out.add(new Delivery(c.name, true, null));
            } catch (Exception e) {
                out.add(new Delivery(c.name, false, e.getMessage()));
            }
        }
        return out;
    }

    private void deliver(Channel c, Alert a) throws Exception {
        switch (c.type) {
            case "slack": postJson(c.url, slack(a), null); break;
            case "teams": postJson(c.url, teams(a), null); break;
            case "discord": postJson(c.url, discord(a), null); break;
            case "webhook": postJson(c.url, webhook(a), c.secret); break;
            case "file": appendFile(c, a); break;
            case "email": email(c, a); break;
            default: throw new IOException("unknown channel type " + c.type);
        }
    }

    private static String emoji(String sev) {
        switch (sev == null ? "" : sev.toLowerCase(Locale.ROOT)) {
            case "critical": return ":rotating_light:";
            case "high": return ":red_circle:";
            case "medium": return ":large_orange_circle:";
            case "low": return ":large_blue_circle:";
            default: return ":information_source:";
        }
    }

    static Object slack(Alert a) {
        StringBuilder b = new StringBuilder();
        for (String l : a.lines) b.append("• ").append(l).append('\n');
        List<Object> blocks = new ArrayList<>();
        blocks.add(Json.obj("type", "header", "text", Json.obj("type", "plain_text", "text", trim(a.title, 150))));
        if (b.length() > 0) blocks.add(Json.obj("type", "section", "text", Json.obj("type", "mrkdwn", "text", trim(b.toString(), 2900))));
        blocks.add(Json.obj("type", "context", "elements", List.of(Json.obj("type", "mrkdwn",
                "text", emoji(a.severity) + " " + a.severity.toUpperCase(Locale.ROOT) + " · sm-maven " + a.tool + (a.link == null ? "" : " · <" + a.link + "|details>")))));
        return Json.obj("text", a.title, "blocks", blocks);
    }

    static Object teams(Alert a) {
        List<Object> body = new ArrayList<>();
        body.add(Json.obj("type", "TextBlock", "size", "Medium", "weight", "Bolder", "text", a.title, "wrap", true));
        body.add(Json.obj("type", "TextBlock", "isSubtle", true, "spacing", "None", "text", a.severity.toUpperCase(Locale.ROOT) + " · sm-maven " + a.tool, "wrap", true));
        for (String l : a.lines.subList(0, Math.min(a.lines.size(), 30))) body.add(Json.obj("type", "TextBlock", "text", "- " + l, "wrap", true, "spacing", "Small"));
        Map<String, Object> card = Json.obj("$schema", "http://adaptivecards.io/schemas/adaptive-card.json", "type", "AdaptiveCard", "version", "1.4", "body", body);
        if (a.link != null) card.put("actions", List.of(Json.obj("type", "Action.OpenUrl", "title", "Details", "url", a.link)));
        return Json.obj("type", "message", "attachments", List.of(Json.obj("contentType", "application/vnd.microsoft.card.adaptive", "content", card)));
    }

    static Object discord(Alert a) {
        int color;
        switch (a.severity) {
            case "critical": color = 0x8B0000; break;
            case "high": color = 0xE53935; break;
            case "medium": color = 0xFB8C00; break;
            case "low": color = 0x1E88E5; break;
            default: color = 0x607D8B;
        }
        StringBuilder b = new StringBuilder();
        for (String l : a.lines) b.append("• ").append(l).append('\n');
        Map<String, Object> embed = Json.obj("title", trim(a.title, 250), "description", trim(b.toString(), 4000), "color", color,
                "footer", Json.obj("text", "sm-maven " + a.tool + " · " + a.severity));
        if (a.link != null) embed.put("url", a.link);
        return Json.obj("embeds", List.of(embed));
    }

    static Object webhook(Alert a) {
        return Json.obj("source", "sm-maven", "tool", a.tool, "title", a.title, "severity", a.severity, "lines", a.lines,
                "link", a.link, "data", a.data, "sentAt", java.time.Instant.now().toString());
    }

    private void postJson(String url, Object payload, String secret) throws HttpException, IOException {
        if (url == null) throw new IOException("channel has no url");
        String body = Json.write(payload, false);
        Map<String, String> h = new LinkedHashMap<>();
        if (secret != null) h.put("X-SM-Maven-Signature", "sha256=" + hmac(secret, body));
        Http.Response r = http.postJson(url, body, h);
        if (!r.ok()) throw new HttpException(url, r.status, r.text());
    }

    static String hmac(String secret, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Hash.toHex(mac.doFinal(body.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void appendFile(Channel c, Alert a) throws IOException {
        if (c.file == null) throw new IOException("file channel has no path");
        Path p = Path.of(c.file);
        if (p.getParent() != null) Files.createDirectories(p.getParent());
        Files.writeString(p, Json.write(webhook(a), false) + "\n", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    private static String trim(String s, int n) { return s == null ? "" : s.length() <= n ? s : s.substring(0, n - 1) + "…"; }

    // ---------------------------------------------------------------- SMTP

    private void email(Channel c, Alert a) throws IOException {
        if (c.host == null || c.from == null || c.to.isEmpty()) throw new IOException("email channel needs host, from and to");
        StringBuilder text = new StringBuilder(a.title).append("\n\n");
        for (String l : a.lines) text.append("- ").append(l).append('\n');
        if (a.link != null) text.append("\n").append(a.link).append('\n');
        text.append("\n-- \nsm-maven ").append(a.tool).append(" (Slash Mark Maven Suite)\n");
        String subject = "[" + a.severity.toUpperCase(Locale.ROOT) + "] " + a.title;
        Smtp.send(c, subject, text.toString());
    }

    static final class Smtp {
        private Socket socket;
        private BufferedReader in;
        private OutputStream out;

        static void send(Channel c, String subject, String text) throws IOException {
            Smtp s = new Smtp();
            boolean implicit = "ssl".equalsIgnoreCase(c.tls) || c.port == 465;
            s.socket = implicit ? SSLSocketFactory.getDefault().createSocket(c.host, c.port) : new Socket(c.host, c.port);
            s.socket.setSoTimeout(30_000);
            s.streams();
            try {
                s.expect(220);
                List<String> caps = s.ehlo();
                if (!implicit && !"none".equalsIgnoreCase(c.tls)) {
                    if (!caps.contains("STARTTLS")) throw new IOException("server does not offer STARTTLS (set tls to none only on trusted networks)");
                    s.cmd("STARTTLS", 220);
                    SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(s.socket, c.host, c.port, true);
                    tls.startHandshake();
                    s.socket = tls;
                    s.streams();
                    s.ehlo();
                }
                if (c.user != null) {
                    String plain = Base64.getEncoder().encodeToString(("\0" + c.user + "\0" + (c.password == null ? "" : c.password)).getBytes(StandardCharsets.UTF_8));
                    s.cmd("AUTH PLAIN " + plain, 235);
                }
                s.cmd("MAIL FROM:<" + addr(c.from) + ">", 250);
                for (String t : c.to) s.cmd("RCPT TO:<" + addr(t) + ">", 250, 251);
                s.cmd("DATA", 354);
                StringBuilder m = new StringBuilder();
                m.append("From: ").append(c.from).append("\r\n");
                m.append("To: ").append(String.join(", ", c.to)).append("\r\n");
                m.append("Subject: =?UTF-8?B?").append(Base64.getEncoder().encodeToString(subject.getBytes(StandardCharsets.UTF_8))).append("?=\r\n");
                m.append("Date: ").append(ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME)).append("\r\n");
                m.append("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n");
                m.append("X-Mailer: sm-maven\r\n\r\n");
                for (String line : text.split("\n", -1)) {
                    if (line.startsWith(".")) m.append('.');
                    m.append(line).append("\r\n");
                }
                m.append(".\r\n");
                s.out.write(m.toString().getBytes(StandardCharsets.UTF_8));
                s.out.flush();
                s.expect(250);
                s.cmd("QUIT", 221);
            } finally {
                try { s.socket.close(); } catch (IOException ignored) {}
            }
        }

        private static String addr(String s) {
            int lt = s.indexOf('<'), gt = s.indexOf('>');
            return lt >= 0 && gt > lt ? s.substring(lt + 1, gt) : s.trim();
        }

        private void streams() throws IOException {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out = socket.getOutputStream();
        }

        private List<String> ehlo() throws IOException {
            out.write("EHLO sm-maven\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            List<String> caps = new ArrayList<>();
            String line;
            while ((line = in.readLine()) != null) {
                if (!line.startsWith("250")) throw new IOException("EHLO rejected: " + line);
                String cap = line.length() > 4 ? line.substring(4).trim().toUpperCase(Locale.ROOT) : "";
                caps.add(cap.split(" ")[0]);
                if (line.length() < 4 || line.charAt(3) == ' ') break;
            }
            return caps;
        }

        private void cmd(String c, int... ok) throws IOException {
            out.write((c + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
            expect(ok);
        }

        private void expect(int... ok) throws IOException {
            String line;
            String last = null;
            while ((line = in.readLine()) != null) {
                last = line;
                if (line.length() < 4 || line.charAt(3) == ' ') break;
            }
            if (last == null) throw new IOException("SMTP connection closed");
            int code;
            try { code = Integer.parseInt(last.substring(0, 3)); } catch (RuntimeException e) { throw new IOException("bad SMTP reply: " + last); }
            for (int o : ok) if (o == code) return;
            throw new IOException("SMTP error: " + last);
        }
    }
}
