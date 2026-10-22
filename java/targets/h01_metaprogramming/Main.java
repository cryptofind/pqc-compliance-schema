package benchmark.h01;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
public class Main {
  static Object create(String className) throws Exception { // GT:H1-REFLECT/def
    Class<?> c = Class.forName(className); // GT:H1-REFLECT
    return c.getDeclaredConstructor().newInstance();
  }
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H1-PROBE
    String algorithm = String.join("", "AES", "/GCM/NoPadding"); // GT:H1-DYNAMIC/src
    Cipher cipher = Cipher.getInstance(algorithm); // GT:H1-DYNAMIC
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp384r1")); // GT:H1-ECDSA-P384
    create("javax.crypto.spec.SecretKeySpec"); // GT:H1-REFLECT/use
  }
}
