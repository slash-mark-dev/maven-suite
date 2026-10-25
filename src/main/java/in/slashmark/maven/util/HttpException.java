package in.slashmark.maven.util;

/** A network or HTTP failure. status is 0 when no response was received. */
public class HttpException extends Exception {
    public final String url;
    public final int status;

    public HttpException(String url, int status, String detail) {
        super(message(url, status, detail));
        this.url = url;
        this.status = status;
    }

    private static String message(String url, int status, String detail) {
        String d = detail == null ? "" : detail.strip();
        if (d.length() > 200) d = d.substring(0, 200) + "...";
        String host;
        try { host = java.net.URI.create(url).getHost(); } catch (RuntimeException e) { host = url; }
        if (status == 0) return "could not reach " + host + ": " + d;
        return host + " answered HTTP " + status + (d.isEmpty() ? "" : ": " + d.replace('\n', ' '));
    }
}
