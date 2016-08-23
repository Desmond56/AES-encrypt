import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtils {
    /**
     * 加密
     *
     * @param strKey 密钥
     * @param strIn  待加密串
     * @return * @throws Exception
     */
    public static String encrypt(String strKey, String strIn) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes());
            cipher.init(
                    Cipher.ENCRYPT_MODE, new SecretKeySpec(strKey.getBytes(), "AES"), iv);
            byte[] encrypted = cipher.doFinal(strIn.getBytes());
            return new BASE64Encoder().encode(encrypted);
        } catch (Exception e) {
            System.out.println(e);
            return "";
        }
    }

    /**
     * 解密
     *
     * @param strKey 密钥
     * @param strIn  待加密串
     * @return
     */
    public static String decrypt(String strKey, String strIn) {
        try {
            byte[] encrypted1 = new BASE64Decoder().decodeBuffer(strIn);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keyspec = new SecretKeySpec(strKey.getBytes(), "AES");
            IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keyspec, iv);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            return originalString;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static void main(String aregs[]) {
        String str_test = "胡汉三";
        String key = "aaaaaaaaaaaaaaaa";
        try {
            System.out.println("加密前" + str_test);
            String encrypt = AESUtils.encrypt(key, str_test);
            System.out.println("加密后" + encrypt);
            String decrypt_word = AESUtils.decrypt(key, encrypt);
            System.out.println("解密后" + decrypt_word);
        } catch(Exception e){
            System.out.println(e);
        }
    }
}