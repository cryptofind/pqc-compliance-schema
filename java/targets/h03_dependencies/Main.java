package benchmark.h03;
import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.SecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
public class Main {
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H3-PROBE
    Security.addProvider(new BouncyCastleProvider()); // GT:H3-BC-PROVIDER
    MessageDigest sha3 = MessageDigest.getInstance("SHA3-256", "BC"); // GT:H3-BC-SHA3
    Mac hmac = Mac.getInstance("HmacSHA1"); // GT:H3-HMAC-SHA1
    SecureRandom random = SecureRandom.getInstanceStrong(); // GT:H3-RNG
  }
}
