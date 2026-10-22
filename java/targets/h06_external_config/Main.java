package benchmark.h06;
import javax.crypto.Cipher;
import java.security.*;
public class Main {
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H6-PROBE
    String algorithm = System.getProperty("crypto.kex", "X25519"); // GT:H6-SYSTEM-PROPERTY
    KeyPairGenerator selected = KeyPairGenerator.getInstance(algorithm); // GT:H6-CONFIG-SELECTED
    String cipherName = System.getenv().getOrDefault("APP_CIPHER", "AES/GCM/NoPadding"); // GT:H6-ENV
    Cipher cipher = Cipher.getInstance(cipherName); // GT:H6-ENV-USE
    // Registry item intentionally exists but is not selected by the default configuration.
    String unused = "DES/ECB/PKCS5Padding"; // GT:H6-REGISTRY (not selected)
  }
}
