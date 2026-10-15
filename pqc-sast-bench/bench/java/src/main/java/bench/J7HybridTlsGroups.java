package bench;
import javax.net.ssl.*;
/** J7: TLS client whose key-exchange groups are left to JDK defaults (named groups set in java.security / system properties). */
public class J7HybridTlsGroups {
    public static SSLSocket connect(String host) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(null, null, null);
        return (SSLSocket) ctx.getSocketFactory().createSocket(host, 443);
    }
}
