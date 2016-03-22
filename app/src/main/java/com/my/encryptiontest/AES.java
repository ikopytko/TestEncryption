package com.my.encryptiontest;

import android.util.Base64;
import android.util.Log;

import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Ivan on 9/10/2015.
 */
public class AES {

    public AES(String data) {
        try {
            String encrypt = Encrypt(data);

            String decrypt = Decrypt(encrypt);

            Log.d("TTAG", encrypt);
            Log.d("TTAG", decrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String Encrypt(String raw) throws Exception {
        Cipher c = getCipher(Cipher.ENCRYPT_MODE);

        byte[] encryptedVal = c.doFinal(raw.getBytes("UTF-8"));
        return Base64.encodeToString(encryptedVal, Base64.DEFAULT);
    }

    private static String Decrypt(String encrypted) throws Exception {

        byte[] decodedValue = Base64.decode(encrypted, Base64.DEFAULT);

        Cipher c = getCipher(Cipher.DECRYPT_MODE);
        byte[] decValue = c.doFinal(decodedValue);

        return new String(decValue);
    }

    private static Cipher getCipher(int mode) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding"/*, new SunJCE()*/);

        //a random Init. Vector. just for testing
        byte[] iv = "e675f725e675f725".getBytes("UTF-8");

        c.init(mode, generateKey(), new IvParameterSpec(iv));
        return c;
    }

    private static Key generateKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        char[] password = "Pass@word1".toCharArray();
        byte[] salt = "S@1tS@1t".getBytes("UTF-8");

        KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        byte[] encoded = tmp.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }
}
