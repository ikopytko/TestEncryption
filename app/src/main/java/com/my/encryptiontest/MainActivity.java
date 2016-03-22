package com.my.encryptiontest;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
       // Fabric.with(this, new Crashlytics());
        setContentView(R.layout.activity_main);

        String data = "Something to decrypt";

        if (new Random().nextBoolean()) {
            throw new StackOverflowError("Custom error! O_O");
        }

        try {
            Log.d("TTAG", encrypt(data));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encrypt(String raw) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] modulusBytes = Base64.decode("3Oc0f5Atw48+8Pf6m48h3qdeP8m0FpepQPxVFIFDC78dV59QiWgmthWOBiDoQYHUVH1ZLH1W6kj9ZsF+9+MEfWq1/6Oi0tBL3TB4Zl/RMHXRxJMWY0vK81xSFNZ0ou+RmZBFTU0J7TLlwLelAMy9tjTzWW8GlD6qBeZs4HKYXO8=", Base64.DEFAULT);
        byte[] exponentBytes = Base64.decode("AQAB", Base64.DEFAULT);
        BigInteger modulus = new BigInteger(1, modulusBytes );
        BigInteger exponent = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec rsaPubKey = new RSAPublicKeySpec(modulus, exponent);

        InputStream inStream = getResources().openRawResource(R.raw.public_key);

        //PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(convertStreamToByteArray(inStream)); // for private
        X509EncodedKeySpec spec = new X509EncodedKeySpec(convertStreamToByteArray(inStream)); // for public

        KeyFactory fact = KeyFactory.getInstance("RSA");

        PublicKey pubKey = fact.generatePublic(spec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] plainBytes = raw.getBytes("UTF-8");
        byte[] cipherData = cipher.doFinal(plainBytes);
        byte[] base64String = Base64.encode(cipherData, Base64.DEFAULT);

        return new String(base64String);
    }


    public static byte[] convertStreamToByteArray(InputStream is) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buff = new byte[10240];
        int i;
        try {
            while ((i = is.read(buff, 0, buff.length)) > 0) {
                baos.write(buff, 0, i);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return baos.toByteArray(); // be sure to close InputStream in calling function
    }
}
