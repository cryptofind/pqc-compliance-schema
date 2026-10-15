package bench;
import java.security.*;
/** J1: RSA-2048 key pair and SHA256withRSA signature through JCA. */
public class J1RsaSign {
    public static byte[] sign(byte[] data) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }
}
