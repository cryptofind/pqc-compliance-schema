package benchmark.h08;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
public class Main {
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H8-PROBE
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding"); // GT:H8-AES-GCM
    Cipher des = Cipher.getInstance("DES/ECB/PKCS5Padding"); // GT:H8-DES-ECB
    Mac hmac1 = Mac.getInstance("HmacSHA1"); // GT:H8-HMAC-SHA1
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048); // GT:H8-RSA2048
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp256r1")); // GT:H8-P256
    String mlkem = "ML-KEM-768"; // GT:H8-MLKEM (algorithm identifier; provider-dependent)
    String mldsa = "ML-DSA-65"; // GT:H8-MLDSA (algorithm identifier; provider-dependent)
    String hybrid = "X25519+ML-KEM-768"; // GT:H8-HYBRID (composition descriptor)
  }
}
