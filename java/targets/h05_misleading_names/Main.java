package benchmark.h05;
import javax.crypto.Cipher;
import java.security.*;
public class Main {
  // Names intentionally disagree with the actual algorithm; compare against neutral twins.
  static Cipher pqReadyEngine() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); } // GT:H5-PAIR1-MISLEADING
  static Cipher secureEnvelope() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); } // GT:H5-PAIR1-NEUTRAL
  static KeyPairGenerator quantumShield() throws Exception { return KeyPairGenerator.getInstance("RSA"); } // GT:H5-PAIR2-MISLEADING
  static KeyPairGenerator keyPairFactory() throws Exception { return KeyPairGenerator.getInstance("RSA"); } // GT:H5-PAIR2-NEUTRAL
  static String mlkemLabel() { return "ML-KEM-768"; } // GT:H5-DECOY (label only; no crypto API)
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H5-PROBE
    pqReadyEngine(); secureEnvelope(); quantumShield(); keyPairFactory(); mlkemLabel();
  }
}
