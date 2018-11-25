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
    
    // DH - methods
    private void DHGenerateAlice(Abonent mainAbonent) throws Exception {
    	// АЛИСА создаёт ключ 2048 бит
    	SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048, secureRandom);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();
        
        // АЛИСА создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());
        // отправляем строку Бобу
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();
        String alicePubKeyEncStr = Base64.encodeBase64String(alicePubKeyEnc);
        // получает его ключ, сессионную пару и параметры шифрования
        String[] result = mainAbonent.DHGenerateBob(alicePubKeyEncStr);
             
        byte[] bobPubKeyEnc = Base64.decodeBase64(result[0]); 
        byte[] cipherString1 = Base64.decodeBase64(result[1]);
        byte[] cipherString2 = Base64.decodeBase64(result[2]); 
        byte[] encodedParams = Base64.decodeBase64(result[3]);
        
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
    
    private String[] DHGenerateBob(String alicePubKeyEncStr) throws Exception {
        // Боб из байтов АЛИСЫ формирует её публичный ключ 
    	byte[] alicePubKeyEnc = Base64.decodeBase64(alicePubKeyEncStr);
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
        
        // перегенерировать байты в текст и передать
        String[] resultString = new String[4];
        resultString[0] = Base64.encodeBase64String(bobPubKeyEnc);
        resultString[1] = Base64.encodeBase64String(cipherString1);
        resultString[2] = Base64.encodeBase64String(cipherString2);
        resultString[3] = Base64.encodeBase64String(encodedParams);
        
        return resultString;
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
