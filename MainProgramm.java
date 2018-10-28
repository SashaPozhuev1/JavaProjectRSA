import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainProgramm {
	public static void main (String[] arguments) throws
	NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException,
	UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		Abonent abonent1 = new Abonent();
		Abonent abonent2 = new Abonent();
		
		// каждый раз разные ключи
		for(int i = 0; i < 2; i++) {
			abonent1.exchangeKeys(abonent2);
			byte[] x = abonent1.encrypt("Hello abonent2!\n");
			System.out.print(x + "\n");
		
			String y = abonent2.decrypt(x);
			System.out.print(y + "\n");		
		}		
	}
}
