package signmessage;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Main {

	public static void main(String[] args) throws Exception {
		//Generate public and private keys:
		KeyPair pair = null;
		pair = SHA256.generateKeyPair(2048);
		PrivateKey priv = pair.getPrivate();
		PublicKey pub = pair.getPublic();
		
		//Store keys to text files:
		SHA256.storePrivateKey(priv, "privkey");
		SHA256.storePublicKey(pub, "key");
		
		//Retrieve keys from text files:
		PrivateKey sameKey = SHA256.getPrivateKey("privkey");
		PublicKey sameKeyPub = SHA256.getPublicKey("Key");
		
		//Create signature:
		String signature = SHA256.Sign("test", sameKey);
		System.out.println(signature);
		
		//Verify signature:
		boolean verifyKey = SHA256.verify("test", signature, sameKeyPub);
		System.out.println("Verified signature= " + verifyKey);

	}

}
