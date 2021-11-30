package demo.java;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;


/**
 * @Title: AES加密算法
 * @ClassName: com.worldskills.system.utils.AesUtils.java
 * @Description:
 *
 * @Copyright 2020-2021 捷安高科 - Powered By 研发中心
 * @author: 王延飞
 * @date:  2021/11/29 20:43
 * @version V1.0
 */
public class AesUtils {

    private static final Logger log = LoggerFactory.getLogger(AesUtils.class);

    private static final String key = "123456jiean@cloud@train123456789";
    /**
     * @Title: 加密
     * @MethodName:  encrypt
     * @param value 明文字符
     * @Return java.lang.String
     * @Exception
     * @Description:
     *
     * @author: 王延飞
     * @date:  2021/11/30 9:05
     */
    public static String encrypt(String value) {

        try {
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
            byte[] encrypted = cipher.doFinal(value.getBytes());
            String encryptedStr = Base64.encodeBase64String(encrypted);
            return encryptedStr;
        } catch (Exception ex) {
            log.error("[AES加密异常],异常信息{}",ex);
            return null;
        }
    }
    /**
     * @Title: 解密
     * @MethodName:  decrypt
     * @param encrypted 密文字符
     * @Return java.lang.String
     * @Exception
     * @Description:
     *
     * @author: 王延飞
     * @date:  2021/11/30 9:05
     */
    public static String decrypt(String encrypted) {

        try {
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
            String decryptStr = new String(original);
            return decryptStr;
        } catch (Exception ex) {
            log.error("[AES解密异常],异常信息{}",ex);
            return null;
        }

    }

    public static void main(String[] args) {

       String input = "123456";
        String encrypted = AesUtils.encrypt(input);
        System.out.println("[密文数据]:"+ encrypted);

        String decrypted = AesUtils.decrypt(encrypted);
        System.out.println("[明文数据]:"+decrypted);
    }

}
