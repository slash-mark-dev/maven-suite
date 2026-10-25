package in.slashmark.maven.cli;

/** Bad arguments: exit code 2 and a short hint. */
public class UsageException extends RuntimeException {
    public UsageException(String message) { super(message); }
}
