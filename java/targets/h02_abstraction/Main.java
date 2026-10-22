package benchmark.h02;
import javax.crypto.Cipher;
import java.security.*;
import java.util.function.Supplier;
public class Main {
  interface CryptoFactory { Cipher build() throws Exception; }
  static Cipher viaFactory(CryptoFactory factory) throws Exception { return factory.build(); } // GT:H2-FACTORY
  static Supplier<MessageDigest> digestSupplier() { return () -> { try { return MessageDigest.getInstance("SHA-384"); } catch (Exception e) { throw new RuntimeException(e); } }; } // GT:H2-CLOSURE
  static Cipher wrapped() throws Exception { return Cipher.getInstance("AES/GCM/NoPadding"); } // GT:H2-WRAPPER
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H2-PROBE
    viaFactory(() -> Cipher.getInstance("AES/CBC/PKCS5Padding")); // GT:H2-FACTORY/use
    digestSupplier().get(); // GT:H2-CLOSURE/use
    wrapped(); // GT:H2-WRAPPER/use
  }
}
