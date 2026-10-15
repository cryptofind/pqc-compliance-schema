package bench;
import java.io.InputStream;
import java.security.*;
import java.util.Properties;
/** J6: crypto-agile configuration; algorithm names come from crypto.properties. */
public class J6ConfigDriven {
    public static byte[] sign(byte[] data) throws Exception {
        Properties p = new Properties();
        try (InputStream in = J6ConfigDriven.class.getResourceAsStream("/crypto.properties")) { p.load(in); }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(p.getProperty("keypair.algorithm"));
        kpg.initialize(Integer.parseInt(p.getProperty("keypair.size")));
        Signature s = Signature.getInstance(p.getProperty("signature.algorithm"));
        s.initSign(kpg.generateKeyPair().getPrivate());
        s.update(data);
        return s.sign();
    }
}
