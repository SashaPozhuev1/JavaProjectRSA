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
            	DHGenerateUser(mainAbonent);
            }
        }
        catch(Exception ex) {
            ex.printStackTrace();
        }
    }
    
    // DH - methods
    private void DHGenerateUser(Abonent mainAbonent) throws Exception {
    	// ЮЗЕР создаёт ключ 2048 бит
    	SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator userKpairGen = KeyPairGenerator.getInstance("DH");
        userKpairGen.initialize(2048, secureRandom);
        KeyPair userKpair = userKpairGen.generateKeyPair();
        
        // ЮЗЕР создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement userKeyAgree = KeyAgreement.getInstance("DH");
        userKeyAgree.init(userKpair.getPrivate());
        // отправляем строку АДМИНу
        byte[] userPubKeyEnc = userKpair.getPublic().getEncoded();
        String userPubKeyEncStr = Base64.encodeBase64String(userPubKeyEnc);
        // получает его ключ, сессионную пару и параметры шифрования
        String[] result = mainAbonent.DHGenerateAdmin(userPubKeyEncStr);
             
        byte[] adminPubKeyEnc = Base64.decodeBase64(result[0]); 
        byte[] cipherString1 = Base64.decodeBase64(result[1]);
        byte[] cipherString2 = Base64.decodeBase64(result[2]); 
        byte[] encodedParams = Base64.decodeBase64(result[3]);
        
        // получает из байтов ключ АДМИНА и добавляет к общему секрету
        KeyFactory userKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(adminPubKeyEnc);
        PublicKey adminPubKey = userKeyFac.generatePublic(x509KeySpec); 
        
        userKeyAgree.doPhase(adminPubKey, true);
        byte[] userSharedSecret = userKeyAgree.generateSecret();
        
        // формирует AES ключ	
        SecretKeySpec userAesKey = new SecretKeySpec(userSharedSecret, 0, 16, "AES");
        // применяет параметры шифрования и свой AES ключ
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParams);      
        // создаёт шифр с полученными параметрами шифрования
        Cipher userCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        userCipher.init(Cipher.DECRYPT_MODE, userAesKey, aesParams);
        
        // расшифровавыет сессионную пару
        sessionPair_[0] = new String(userCipher.doFinal(cipherString1));
        sessionPair_[1] = new String(userCipher.doFinal(cipherString2));
    }
    
    private String[] DHGenerateAdmin(String userPubKeyEncStr) throws Exception {
        // АДМИН из байтов АЛИСЫ формирует её публичный ключ 
    	byte[] userPubKeyEnc = Base64.decodeBase64(userPubKeyEncStr);
        KeyFactory adminKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(userPubKeyEnc);
        PublicKey userPubKey = adminKeyFac.generatePublic(x509KeySpec); 

        // АДМИН получает параметры ключа АЛИСЫ и на их основе создаёт пару собственных ключей
        DHParameterSpec dhParamFromuserPubKey = ((DHPublicKey)userPubKey).getParams();
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator adminKpairGen = KeyPairGenerator.getInstance("DH");
        adminKpairGen.initialize(dhParamFromuserPubKey, secureRandom);
        KeyPair adminKpair = adminKpairGen.generateKeyPair();

        // АДМИН создаёт DH KeyAgreement объект (приватный ключ) и инвертирует публичный ключ в байты
        KeyAgreement adminKeyAgree = KeyAgreement.getInstance("DH");
        adminKeyAgree.init(adminKpair.getPrivate());
        byte[] adminPubKeyEnc = adminKpair.getPublic().getEncoded();
        // добавляет ключ Алисы к общему секрету
        adminKeyAgree.doPhase(userPubKey, true);
        byte[] adminSharedSecret = adminKeyAgree.generateSecret();
        
        // формирует AES ключ и шифрует им свой секретный ключ
        SecretKeySpec adminAesKey = new SecretKeySpec(adminSharedSecret, 0, 16, "AES");
        // создаёт шифр, применяет его и параметры шифрования
        Cipher adminCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        adminCipher.init(Cipher.ENCRYPT_MODE, adminAesKey);
        
        // нужно передать зашифрованный текст и параметры шифрования
        byte[] cipherString1 = adminCipher.doFinal(sessionPair_[0].getBytes());
        byte[] cipherString2 = adminCipher.doFinal(sessionPair_[1].getBytes());
        byte[] encodedParams = adminCipher.getParameters().getEncoded();
        
        // перегенерировать байты в текст и передать
        String[] resultString = new String[4];
        resultString[0] = Base64.encodeBase64String(adminPubKeyEnc);
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
