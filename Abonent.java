import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class Abonent {
	private Cipher cipher_;
	private KeyPairGenerator keyGen_;

	public KeyPair pg_;
	public PublicKey openKey_;
	private PrivateKey secretKey_;
	
	//public PublicKey otherOpenKey_;// ?

	private byte[] openMessage_;	  // пишем свои, расшифровываем чужие
	private byte[] secretMessage_; // приходят чужие, отправляем свои
	
	// необходимо различать свои и чужие сообщения
	public Abonent() throws NoSuchAlgorithmException, NoSuchPaddingException{
		cipher_ = Cipher.getInstance( "RSA" );
	}
	
	public void exchangeKeys(Abonent other) throws NoSuchAlgorithmException{
		makeKeyGen(other);
	}
	
	private void makeKeyGen(Abonent other) throws NoSuchAlgorithmException{
		keyGen_ = KeyPairGenerator.getInstance( "RSA" );
		keyGen_.initialize(2048);
		
		pg_ = keyGen_.genKeyPair();		
		openKey_ = pg_.getPublic();
	    	secretKey_ = pg_.getPrivate();
	    
	    	other.makeMyKey(pg_, openKey_);
	}
	
	// тут лучше попросить вызвать другой приватный метод и отобрать открытые ключи у собеседника
	public void makeMyKey(KeyPair pg, PublicKey openKey) {
		pg_ = pg;
		openKey_ = openKey;
		setSecretKey();
		//other.otherOpenKey_ = openKey_; // нет?
	}
	
	private void setSecretKey() {
		secretKey_ = pg_.getPrivate();
	}
	
	public byte[] encrypt(String openMessage) throws InvalidKeyException,
	UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		cipher_.init( Cipher.ENCRYPT_MODE, openKey_ );
		openMessage_ = openMessage.getBytes("UTF-8");    // а надо ли?
	    	secretMessage_ = cipher_.doFinal( openMessage_ );//
	    	return secretMessage_; // если что, можно toString()
	}
	
	public String decrypt(byte[] secretMessage) throws InvalidKeyException,
	IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		cipher_.init( Cipher.DECRYPT_MODE, secretKey_ );	
	    	openMessage_ = cipher_.doFinal(secretMessage);
	    	return new String(openMessage_, "UTF-8");
	}
}
