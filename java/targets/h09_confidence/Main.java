package benchmark.h09;
import javax.crypto.Cipher;
import java.security.*;
public class Main {
  static final int KEY_BITS = 256; // GT:H9-C2/src
  static final String ALGORITHM = "AES/GCM/NoPadding"; // GT:H9-C1/src
  static Cipher direct() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); } // GT:H9-C1
  static Cipher constantBased() throws Exception { return Cipher.getInstance(ALGORITHM); } // GT:H9-C2
  static KeyPairGenerator keyGen() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(3072); return g; } // GT:H9-C3
  static String conditional(boolean flag) { return flag ? "SHA-384" : "SHA3-256"; } // GT:H9-C4
  static String indirect(String name) { return name; } // GT:H9-C5 (identity unresolved without caller)
  static String external() { return System.getenv("H9_ALGORITHM"); } // GT:H9-C6
  static String deadBranch() { if (false) return "DES/ECB/PKCS5Padding"; return "AES/GCM/NoPadding"; } // GT:H9-C7
  static String decoy() { return "ML-KEM-768"; } // GT:H9-DECOY (label only)
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H9-PROBE
    direct(); constantBased(); keyGen(); conditional(true); indirect("SHA-256"); external(); deadBranch(); decoy();
  }
}
