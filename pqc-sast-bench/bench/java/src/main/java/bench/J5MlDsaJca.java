package bench;
import java.security.*;
/** J5: ML-DSA-65 signatures through JCA (JDK 24+, JEP 497). */
public class J5MlDsaJca {
    public static byte[] sign(byte[] data) throws GeneralSecurityException {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65").generateKeyPair();
        Signature s = Signature.getInstance("ML-DSA");
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }
}
