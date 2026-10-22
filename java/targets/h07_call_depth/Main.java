package benchmark.h07;
import javax.crypto.Cipher;
import java.security.*;
public class Main {
  static void level0() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); } // GT:H7-A-D0
  static void level1() throws Exception { level0(); } // GT:H7-A-D1
  static void level2() throws Exception { level1(); } // GT:H7-A-D2
  static void level3() throws Exception { level2(); } // GT:H7-A-D3
  static void level4() throws Exception { level3(); } // GT:H7-A-D4
  static void level5() throws Exception { level4(); } // GT:H7-A-D5
  static void level6() throws Exception { level5(); } // GT:H7-A-D6
  static void level7() throws Exception { level6(); } // GT:H7-A-D7
  static void level8() throws Exception { level7(); } // GT:H7-A-D8
  static void level9() throws Exception { level8(); } // GT:H7-A-D9
  static void level10() throws Exception { level9(); } // GT:H7-A-D10
  public static void run() throws Exception {
    MessageDigest probe = MessageDigest.getInstance("SHA-512"); // GT:H7-PROBE
    level10();
  }
}
