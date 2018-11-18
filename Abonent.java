import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import org.apache.commons.codec.binary.Base64;

public class Abonent {
    // AES keys
    private String[] sessionPair_ = new String[2];
    
    public Abonent(Abonent mainAbonent) {
        try {
            // AES key generation
            if(mainAbonent == null) {    
                // Random strings 
                SecureRandom random = new SecureRandom();
                char[] alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();
                char[][] strings = new char[2][16];
                for(int str = 0; str < 2; ++str) {
                    for (int i = 0; i < 16; ++i) {
                        strings[str][i] = alphanum[random.nextInt(alphanum.length)];
                    }
                    sessionPair_[str] = new String(strings[str]);
                }            
            }
            else{
                // RSA key generation
                SecureRandom secureRandom = new SecureRandom(); // mb insert byte;
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance( "RSA" ); 
                keyGen.initialize(2048, secureRandom);
                KeyPair pg = keyGen.genKeyPair();
                Cipher cipher = Cipher.getInstance( "RSA" );
                   
                getSession(mainAbonent, pg, cipher);
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private void getSession(Abonent mainAbonent, KeyPair pg, Cipher cipher) {
        try {
            for(int i = 0; i < 2; ++i) {
                sessionPair_[i] = new String(
                    decryptRSA(
                            mainAbonent.encryptRSA(i, pg.getPublic(), cipher),
                            pg.getPrivate(),
                            cipher
                            )
                    );
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    // RSA methods - ДЛЯ ШИФРОВАНИЯ AES КЛЮЧА
    private byte[] encryptRSA(int elem, PublicKey openKey, Cipher cipher){
        try {
            cipher.init( Cipher.ENCRYPT_MODE, openKey );
            return cipher.doFinal( sessionPair_[elem].getBytes("UTF-8") ); // or toString()
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private String decryptRSA(byte[] secretMessage, PrivateKey secretKey, Cipher cipher){
        try {
        cipher.init( Cipher.DECRYPT_MODE, secretKey );
        return new String(cipher.doFinal(secretMessage), "UTF-8");
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    // AES methods - ДЛЯ ШИФРОВАНИЯ СООБЩЕНИЙ
    public String encrypt(String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(sessionPair_[1].getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(sessionPair_[0].getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());

            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(sessionPair_[1].getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(sessionPair_[0].getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}
