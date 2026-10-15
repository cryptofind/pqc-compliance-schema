package bench;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
/** J2: ECDSA over P-256 through JCA. */
public class J2EcdsaSign {
    public static byte[] sign(byte[] data) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kpg.generateKeyPair().getPrivate());
        s.update(data);
        return s.sign();
    }
}
