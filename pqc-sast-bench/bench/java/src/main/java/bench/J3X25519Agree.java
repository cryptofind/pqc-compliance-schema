package bench;
import java.security.*;
import javax.crypto.KeyAgreement;
/** J3: X25519 key agreement through JCA. */
public class J3X25519Agree {
    public static byte[] agree(PublicKey peer) throws GeneralSecurityException {
        KeyPair kp = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(kp.getPrivate());
        ka.doPhase(peer, true);
        return ka.generateSecret();
    }
}
