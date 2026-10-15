package bench;
import java.security.*;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
/** J4: ML-KEM-768 through the JCA KEM API (JDK 24+, JEP 496). */
public class J4MlKemJca {
    public static SecretKey encapsulate() throws GeneralSecurityException {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
        KEM kem = KEM.getInstance("ML-KEM");
        KEM.Encapsulated enc = kem.newEncapsulator(kp.getPublic()).encapsulate();
        return enc.key();
    }
}
