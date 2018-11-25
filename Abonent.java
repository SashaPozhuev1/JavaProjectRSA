import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;

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
            	DHGenerateAlice(mainAbonent);
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    private void DHGenerateAlice(Abonent mainAbonent) throws Exception {
    	// АЛИСА создаёт ключ 2048 бит
    	SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048, secureRandom);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        
        // АЛИСА создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        // отправляем это Бобу
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
        
        // получает его ключ, сессионную пару и параметры шифрования
        byte[][] result = mainAbonent.DHGenerateBob(alicePubKeyEnc);
              
        byte[] bobPubKeyEnc = result[0]; 
        byte[] cipherString1 = result[1];
        byte[] cipherString2 = result[2]; 
        byte[] encodedParams = result[3];
        
        // получает из байтов ключ БОБА и добавляет к общему секрету
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec); 
        
        aliceKeyAgree.doPhase(bobPubKey, true);
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();
        
        // формирует AES ключ	
        SecretKeySpec aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
        // применяет параметры шифрования и свой AES ключ
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);      
        // создаёт шифр с полученными параметрами шифрования
        Cipher aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);
        
        // расшифровавыет сессионную пару
        sessionPair_[0] = new String(aliceCipher.doFinal(cipherString1));
        sessionPair_[1] = new String(aliceCipher.doFinal(cipherString2));
    }
    
    private byte[][] DHGenerateBob(byte[] alicePubKeyEnc) throws Exception {
        // Боб из байтов АЛИСЫ формирует её публичный ключ 
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec); 

        // БОБ получает параметры ключа АЛИСЫ и на их основе создаёт пару собственных ключей
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey, secureRandom);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // БОБ создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();
        // добавляет ключ Алисы к общему секрету
        bobKeyAgree.doPhase(alicePubKey, true);
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        
        // формирует AES ключ и шифрует им свой секретный ключ
        SecretKeySpec bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");
        // создаёт шифр, применяет его и параметры шифрования
        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
        
        // нужно передать зашифрованный текст и параметры шифрования
        byte[] cipherString1 = bobCipher.doFinal(sessionPair_[0].getBytes());
        byte[] cipherString2 = bobCipher.doFinal(sessionPair_[1].getBytes());
        byte[] encodedParams = bobCipher.getParameters().getEncoded();
        
        System.out.print(encodedParams.length + "\n" + encodedParams.toString() + "\n");
        byte[][] result = new byte[4][];
        result[0] = bobPubKeyEnc;
        result[1] = cipherString1;
        result[2] = cipherString2;
        result[3] = encodedParams;
        
        return result;
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
