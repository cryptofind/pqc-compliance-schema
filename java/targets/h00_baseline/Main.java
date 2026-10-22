package benchmark.h00;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
public class Main {
  public static void run() throws Exception {
    MessageDigest sha512 = MessageDigest.getInstance("SHA-512"); // GT:H0-PROBE
    sha512.digest(new byte[]{1,2,3});
    KeyGenerator aes = KeyGenerator.getInstance("AES"); aes.init(256); SecretKey key = aes.generateKey(); // GT:H0-AES256/src
    Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding"); // GT:H0-AES256-GCM
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(3072); rsa.generateKeyPair(); // GT:H0-RSA3072
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp384r1")); ec.generateKeyPair(); // GT:H0-ECDSA-P384
    Mac hmac = Mac.getInstance("HmacSHA384"); // GT:H0-HMAC-SHA384
    MessageDigest sha3 = MessageDigest.getInstance("SHA3-256"); // GT:H0-SHA3-256
  }
}
