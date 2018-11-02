import javax.crypto.*;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class Abonent {
	private Cipher cipher_;
	private KeyPairGenerator keyGen_;

	private KeyPair pg_;
	public PublicKey openKey_;
	private PrivateKey secretKey_;
	
	public PublicKey otherOpenKey_;

	private byte[] openMessage_;	  // пишем свои, расшифровываем чужие
	private byte[] secretMessage_; // приходят чужие, отправляем свои
	
	private SecureRandom secureRandom;
	
	// необходимо различать свои и чужие сообщения
	public Abonent() throws NoSuchAlgorithmException, NoSuchPaddingException{
		cipher_ = Cipher.getInstance( "RSA" );
		
		keyGen_ = KeyPairGenerator.getInstance( "RSA" );
		keyGen_.initialize(2048, secureRandom);
		
		pg_ = keyGen_.genKeyPair();		
		openKey_ = pg_.getPublic();
	    secretKey_ = pg_.getPrivate();
	 //   System.out.print("opk:" + openKey_ + "\n" + "sck"+ secretKey_ + "\n");
	}
	
	public void exchangeKeys(Abonent other) throws NoSuchAlgorithmException{
		otherOpenKey_ = other.makeMyKey(openKey_);	
	}
	
	public PublicKey makeMyKey(PublicKey openKey) {
		otherOpenKey_ = openKey;
		return openKey_;
	}
	
	public byte[] encrypt(String openMessage) throws InvalidKeyException,
	UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		cipher_.init( Cipher.ENCRYPT_MODE, otherOpenKey_ );
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
