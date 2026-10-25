package in.slashmark.maven.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * HTTP client with an on-disk response cache, retries, safe redirects (credentials are never
 * forwarded to another host) and a small worker pool for parallel requests.
 */
public final class Http {
    /** sm-maven version: from the JAR manifest (Implementation-Version), "1.0.0" when run from classes. */
    public static final String VERSION = java.util.Optional.ofNullable(Http.class.getPackage().getImplementationVersion()).orElse("1.0.0");
    public static final String USER_AGENT = "sm-maven/" + VERSION + " (+https://slashmark.in)";

    /** Cache forever: release artifacts on Maven repositories never change. */
    public static final long FOREVER = -1;
    public static final long NO_CACHE = 0;
    public static final long DEFAULT_TTL = 10 * 60 * 1000L;

    private final HttpClient client;
    private final Path cacheDir;
    private boolean cacheEnabled = true;
    private boolean verbose;
    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicInteger cacheHits = new AtomicInteger();
    private ExecutorService pool;
    private final Map<String, String> hostAuth = new LinkedHashMap<>();

    public Http(Path cacheDir) {
        HttpClient.Builder b = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER);
        ProxySelector ps = proxyFromEnv();
        if (ps != null) b.proxy(ps);
        this.client = b.build();
        this.cacheDir = cacheDir;
    }

    public void setCacheEnabled(boolean on) { cacheEnabled = on; }
    public boolean cacheEnabled() { return cacheEnabled; }
    public void setVerbose(boolean v) { verbose = v; }
    public int requestCount() { return requests.get(); }
    public int cacheHitCount() { return cacheHits.get(); }
    public Path cacheDir() { return cacheDir; }

    /**
     * Registers an Authorization header for one host (e.g. from settings.xml &lt;server&gt;). It is only
     * ever sent to that exact host and port, never on a redirect elsewhere.
     */
    public void setHostAuth(String hostPort, String authorizationHeader) {
        hostAuth.put(hostPort.toLowerCase(Locale.ROOT), authorizationHeader);
    }

    private static ProxySelector proxyFromEnv() {
        String p = firstNonEmpty(System.getenv("HTTPS_PROXY"), System.getenv("https_proxy"),
                System.getenv("HTTP_PROXY"), System.getenv("http_proxy"));
        if (p == null || System.getProperty("https.proxyHost") != null) return null;
        try {
            URI u = URI.create(p.contains("://") ? p : "http://" + p);
            if (u.getHost() == null) return null;
            final ProxySelector proxied = ProxySelector.of(new InetSocketAddress(u.getHost(), u.getPort() > 0 ? u.getPort() : 8080));
            final String[] noProxy = firstNonEmpty(System.getenv("NO_PROXY"), System.getenv("no_proxy"), "").split(",");
            return new ProxySelector() {
                @Override
                public List<java.net.Proxy> select(URI uri) {
                    String h = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
                    if (h.equals("localhost") || h.startsWith("127.") || h.equals("::1") || h.equals("[::1]")) return List.of(java.net.Proxy.NO_PROXY);
                    for (String n : noProxy) {
                        n = n.trim().toLowerCase(Locale.ROOT);
                        if (n.isEmpty()) continue;
                        if (n.equals("*") || h.equals(n) || (n.startsWith(".") ? h.endsWith(n) : h.endsWith("." + n))) return List.of(java.net.Proxy.NO_PROXY);
                    }
                    return proxied.select(uri);
                }

                @Override
                public void connectFailed(URI uri, java.net.SocketAddress sa, IOException ioe) {}
            };
        } catch (RuntimeException e) {
            return null;
        }
    }

    static String firstNonEmpty(String... v) {
        for (String s : v) if (s != null && !s.isBlank()) return s;
        return null;
    }

    // ---------------------------------------------------------------- response type

    public static final class Response {
        public final int status;
        public final byte[] body;
        public final Map<String, String> headers;
        public final String url;
        public final boolean fromCache;
        public final long millis;

        Response(String url, int status, byte[] body, Map<String, String> headers, boolean fromCache, long millis) {
            this.url = url;
            this.status = status;
            this.body = body == null ? new byte[0] : body;
            this.headers = headers;
            this.fromCache = fromCache;
            this.millis = millis;
        }

        public boolean ok() { return status >= 200 && status < 300; }
        public String text() { return new String(body, StandardCharsets.UTF_8); }
        public Object json() { return Json.parse(text()); }
        public String header(String name) { return headers.get(name.toLowerCase(Locale.ROOT)); }
    }

    // ---------------------------------------------------------------- requests

    public Response get(String url) throws HttpException { return get(url, DEFAULT_TTL, null); }

    public Response get(String url, long ttlMillis) throws HttpException { return get(url, ttlMillis, null); }

    /** GET with caching. Non-2xx responses are returned (404 included) rather than thrown. */
    public Response get(String url, long ttlMillis, Map<String, String> headers) throws HttpException {
        return send("GET", url, null, ttlMillis, headers);
    }

    public Response post(String url, String jsonBody, long ttlMillis) throws HttpException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/json");
        return send("POST", url, jsonBody, ttlMillis, h);
    }

    public Response head(String url) throws HttpException { return send("HEAD", url, null, NO_CACHE, null); }

    /** Uncached JSON POST with extra headers (webhooks). */
    public Response postJson(String url, String jsonBody, Map<String, String> headers) throws HttpException {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/json");
        if (headers != null) h.putAll(headers);
        return send("POST", url, jsonBody, NO_CACHE, h);
    }

    /** GET that throws on non-2xx; convenient for APIs where a miss is an error. */
    public Object getJson(String url, long ttl, Map<String, String> headers) throws HttpException {
        Response r = get(url, ttl, headers);
        if (!r.ok()) throw new HttpException(url, r.status, r.text());
        try {
            return r.json();
        } catch (IllegalArgumentException e) {
            throw new HttpException(url, r.status, "invalid JSON: " + e.getMessage());
        }
    }

    public Object getJson(String url) throws HttpException { return getJson(url, DEFAULT_TTL, null); }

    /** Returns the body text for a 2xx response, or null for 404/410. Throws for other failures. */
    public String getTextOrNull(String url, long ttl) throws HttpException {
        Response r = get(url, ttl, null);
        if (r.ok()) return r.text();
        if (r.status == 404 || r.status == 410) return null;
        throw new HttpException(url, r.status, r.text());
    }

    public byte[] getBytesOrNull(String url, long ttl) throws HttpException {
        Response r = get(url, ttl, null);
        if (r.ok()) return r.body;
        if (r.status == 404 || r.status == 410) return null;
        throw new HttpException(url, r.status, r.text());
    }

    private Response send(String method, String url, String body, long ttl, Map<String, String> headers) throws HttpException {
        String key = method + " " + url + (body == null ? "" : "\n" + body);
        boolean useCache = cacheEnabled && ttl != NO_CACHE && !"HEAD".equals(method);
        if (useCache) {
            Response c = readCache(key, url, ttl);
            if (c != null) {
                cacheHits.incrementAndGet();
                return c;
            }
        }
        Response r = network(method, url, body, headers);
        if (useCache && (r.ok() || r.status == 404)) writeCache(key, r, r.status == 404 ? Math.min(ttl < 0 ? DEFAULT_TTL : ttl, DEFAULT_TTL) : ttl);
        return r;
    }

    private Response network(String method, String url, String body, Map<String, String> headers) throws HttpException {
        String current = url;
        String originHost = hostPort(url);
        int attempt = 0;
        int redirects = 0;
        while (true) {
            attempt++;
            long t0 = System.nanoTime();
            try {
                HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(current))
                        .timeout(Duration.ofSeconds(30))
                        .header("User-Agent", USER_AGENT);
                boolean sameHost = hostPort(current).equals(originHost);
                if (headers != null) {
                    for (Map.Entry<String, String> h : headers.entrySet()) {
                        // Never forward credentials to a host other than the one they were given for.
                        if (!sameHost && h.getKey().equalsIgnoreCase("Authorization")) continue;
                        rb.header(h.getKey(), h.getValue());
                    }
                }
                String auth = hostAuth.get(hostPort(current));
                if (auth != null && (headers == null || headers.keySet().stream().noneMatch(k -> k.equalsIgnoreCase("Authorization")))) {
                    rb.header("Authorization", auth);
                }
                if ("POST".equals(method)) rb.POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
                else if ("HEAD".equals(method)) rb.method("HEAD", HttpRequest.BodyPublishers.noBody());
                else rb.GET();
                requests.incrementAndGet();
                HttpResponse<byte[]> resp = client.send(rb.build(), HttpResponse.BodyHandlers.ofByteArray());
                long ms = (System.nanoTime() - t0) / 1_000_000;
                int st = resp.statusCode();
                if (verbose) System.err.println("[http] " + method + " " + current + " -> " + st + " (" + ms + " ms)");
                if (st >= 300 && st < 400 && st != 304) {
                    String loc = resp.headers().firstValue("location").orElse(null);
                    if (loc == null || ++redirects > 5) return toResponse(url, resp, ms);
                    URI next = URI.create(current).resolve(loc);
                    if ("http".equalsIgnoreCase(next.getScheme()) && current.startsWith("https:")) {
                        throw new HttpException(url, st, "refusing redirect from HTTPS to HTTP: " + next);
                    }
                    current = next.toString();
                    attempt = 0;
                    continue;
                }
                if ((st == 429 || st == 502 || st == 503 || st == 504) && attempt <= 2) {
                    long wait = 800L * attempt;
                    String ra = resp.headers().firstValue("retry-after").orElse(null);
                    if (ra != null) try { wait = Math.min(10_000, Long.parseLong(ra.trim()) * 1000); } catch (NumberFormatException ignored) {}
                    sleep(wait);
                    continue;
                }
                return toResponse(url, resp, ms);
            } catch (IOException e) {
                if (attempt <= 2) { sleep(500L * attempt); continue; }
                throw new HttpException(url, 0, describe(e));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new HttpException(url, 0, "interrupted");
            } catch (IllegalArgumentException e) {
                throw new HttpException(url, 0, "invalid URL: " + e.getMessage());
            }
        }
    }

    private static String describe(IOException e) {
        String m = e.getMessage();
        if (e instanceof java.net.ConnectException) return "connection refused" + (m == null ? "" : " (" + m + ")");
        if (e instanceof java.net.http.HttpTimeoutException) return "timed out";
        if (e instanceof java.net.UnknownHostException) return "unknown host " + m;
        if (e instanceof javax.net.ssl.SSLException) return "TLS error: " + m;
        return e.getClass().getSimpleName() + (m == null ? "" : ": " + m);
    }

    private static Response toResponse(String url, HttpResponse<byte[]> r, long ms) {
        Map<String, String> h = new LinkedHashMap<>();
        r.headers().map().forEach((k, v) -> { if (!v.isEmpty()) h.put(k.toLowerCase(Locale.ROOT), v.get(0)); });
        return new Response(url, r.statusCode(), r.body(), h, false, ms);
    }

    public static String hostPort(String url) {
        try {
            URI u = URI.create(url);
            int port = u.getPort();
            if (port < 0) port = "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
            return (u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT)) + ":" + port;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ---------------------------------------------------------------- cache

    private Path cacheFile(String key) {
        String h = Hash.sha256Hex(key.getBytes(StandardCharsets.UTF_8));
        return cacheDir.resolve("http").resolve(h.substring(0, 2)).resolve(h);
    }

    private Response readCache(String key, String url, long ttl) {
        if (cacheDir == null) return null;
        Path f = cacheFile(key);
        try {
            if (!Files.isRegularFile(f)) return null;
            long age = System.currentTimeMillis() - Files.getLastModifiedTime(f).toMillis();
            if (ttl > 0 && age > ttl) return null;
            byte[] all = Files.readAllBytes(f);
            int nl = 0;
            while (nl < all.length && all[nl] != '\n') nl++;
            String head = new String(all, 0, nl, StandardCharsets.UTF_8);
            int status = Integer.parseInt(head.trim());
            // A cached "not found" never lives longer than the default TTL, even for forever lookups.
            if (status == 404 && age > DEFAULT_TTL) return null;
            byte[] body = new byte[Math.max(0, all.length - nl - 1)];
            System.arraycopy(all, Math.min(all.length, nl + 1), body, 0, body.length);
            return new Response(url, status, body, new LinkedHashMap<>(), true, 0);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private void writeCache(String key, Response r, long ttl) {
        if (cacheDir == null) return;
        Path f = cacheFile(key);
        try {
            Files.createDirectories(f.getParent());
            Path tmp = f.resolveSibling(f.getFileName() + ".tmp" + Thread.currentThread().getId());
            byte[] head = (r.status + "\n").getBytes(StandardCharsets.UTF_8);
            byte[] all = new byte[head.length + r.body.length];
            System.arraycopy(head, 0, all, 0, head.length);
            System.arraycopy(r.body, 0, all, head.length, r.body.length);
            Files.write(tmp, all);
            Files.move(tmp, f, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException | RuntimeException ignored) {
            // cache is best effort
        }
    }

    public long clearCache() throws IOException {
        if (cacheDir == null || !Files.exists(cacheDir.resolve("http"))) return 0;
        long[] n = {0};
        try (var s = Files.walk(cacheDir.resolve("http"))) {
            s.sorted(java.util.Comparator.reverseOrder()).forEach(p -> {
                try { if (Files.isRegularFile(p)) n[0]++; Files.deleteIfExists(p); } catch (IOException ignored) {}
            });
        }
        return n[0];
    }

    // ---------------------------------------------------------------- parallelism

    private synchronized ExecutorService pool() {
        if (pool == null) {
            int n = 8;
            try { n = Integer.parseInt(System.getenv().getOrDefault("SM_MAVEN_PARALLEL", "8")); } catch (NumberFormatException ignored) {}
            pool = Executors.newFixedThreadPool(Math.max(1, Math.min(32, n)), r -> {
                Thread t = new Thread(r, "sm-maven-http");
                t.setDaemon(true);
                return t;
            });
        }
        return pool;
    }

    /** Runs fn over every item in parallel and returns the results in input order. Exceptions are captured per item. */
    public <T, R> List<Result<R>> parallel(List<T> items, ThrowingFunction<T, R> fn) {
        List<Future<Result<R>>> fs = new ArrayList<>();
        for (T it : items) {
            fs.add(pool().submit(() -> {
                try {
                    return Result.ok(fn.apply(it));
                } catch (Exception e) {
                    return Result.<R>fail(e);
                }
            }));
        }
        List<Result<R>> out = new ArrayList<>();
        for (Future<Result<R>> f : fs) {
            try {
                out.add(f.get());
            } catch (Exception e) {
                out.add(Result.fail(e));
            }
        }
        return out;
    }

    public <T, R> List<R> parallelOrNull(List<T> items, ThrowingFunction<T, R> fn) {
        List<R> out = new ArrayList<>();
        for (Result<R> r : parallel(items, fn)) out.add(r.value);
        return out;
    }

    @FunctionalInterface
    public interface ThrowingFunction<T, R> {
        R apply(T t) throws Exception;
    }

    public static final class Result<R> {
        public final R value;
        public final Exception error;

        private Result(R v, Exception e) { value = v; error = e; }

        static <R> Result<R> ok(R v) { return new Result<>(v, null); }
        static <R> Result<R> fail(Exception e) { return new Result<>(null, e); }
        public boolean ok() { return error == null; }
    }

    public static <T> Function<T, T> identity() { return t -> t; }

    public static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
