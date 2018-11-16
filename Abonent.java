import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;
import java.security.*;

public class Abonent {
	private SecureRandom secureRandom;
	static private int counter_ = 0;
	//private Boolean firstAbonent_ = false;
	static private Abonent mainAbonent_;
	
	// RSA
	private Cipher cipher_;
	private KeyPairGenerator keyGen_;
	
	private KeyPair pg_;
	private PublicKey openKey_;
	private PrivateKey secretKey_;
	// private PublicKey otherOpenKey_;
	
	// AES
	String sessionKey_ = "Bar12345Bar12345"; // 128 bit key
    	String sessionInitVector_ = "RandomInitVector"; // 16 bytes
	
	public Abonent() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		// RSA key generation
		secureRandom = new SecureRandom(); // insert byte;
		cipher_ = Cipher.getInstance( "RSA" );
		
		keyGen_ = KeyPairGenerator.getInstance( "RSA" );
		keyGen_.initialize(2048, secureRandom);
		
		pg_ = keyGen_.genKeyPair();		
		openKey_ = pg_.getPublic();
	    secretKey_ = pg_.getPrivate();
	    
	    // AES key generation
	    if(counter_ == 0) {	
	    	mainAbonent_ = this;
	    	// firstAbonent_ = true;
	    	// randomize sessionKey_;
	    	// randomize sessionInitVector_;
	    }
	    else{
	    	getSession(mainAbonent_, openKey_);
	    }
	    counter_++;
	    System.out.print("opk:" + openKey_ + "\n" + "sck"+ secretKey_ + "\n");
	}
	
	private void getSession(Abonent mainAbonent, PublicKey openKey) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		// decrypt
		sessionKey_ = new String(decryptRSA(mainAbonent.encryptRSA(mainAbonent.sessionKey_, openKey)));
		sessionInitVector_ = new String(decryptRSA(mainAbonent.encryptRSA(mainAbonent.sessionInitVector_, openKey)));
	}

	public byte[] encryptRSA(String openMessage, PublicKey openKey) throws InvalidKeyException,
	UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		cipher_.init( Cipher.ENCRYPT_MODE, openKey );
		return cipher_.doFinal( openMessage.getBytes("UTF-8") ); // or toString()
	}

	public String decryptRSA(byte[] secretMessage) throws InvalidKeyException,
	IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		cipher_.init( Cipher.DECRYPT_MODE, secretKey_ );
		return new String(cipher_.doFinal(secretMessage), "UTF-8");
	}

	public static String encrypt(String key, String initVector, String value) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(value.getBytes("UTF-8"));

			return new String(encrypted, "UTF-8");
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public static String decrypt(String key, String initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

			byte[] original = cipher.doFinal(encrypted.getBytes("UTF-8"));

			return new String(original, "UTF-8");
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}
}
