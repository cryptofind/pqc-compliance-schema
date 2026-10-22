package benchmark.h04;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
public class Main {
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H4-PROBE
    KeyPairGenerator x = KeyPairGenerator.getInstance("X25519"); x.generateKeyPair(); // GT:H4-U1-CLASSICAL
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048); rsa.generateKeyPair(); // GT:H4-U2-RSA
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp256r1")); ec.generateKeyPair(); // GT:H4-U3-ECDSA
    Cipher aes = Cipher.getInstance("AES/GCM/NoPadding"); // GT:H4-U4-AES
    // PQC algorithms may require a provider (for example, Bouncy Castle); strings are intentional test evidence.
    String pqKem = "ML-KEM-768"; // GT:H4-U5-MLKEM
    String pqSig = "ML-DSA-65"; // GT:H4-U6-MLDSA
    String hybrid = "X25519+ML-KEM-768"; // GT:H4-U7-HYBRID
  }
}
