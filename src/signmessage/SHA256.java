package signmessage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SHA256 {
	
	public static void storePrivateKey(PrivateKey privateKey, String textFile) throws IOException {
		byte[] privateKeybytes = privateKey.getEncoded();
		
		File newFile = new File(textFile + ".txt");
		FileOutputStream fop = new FileOutputStream(newFile);
		fop.write(privateKeybytes);
		fop.close();
	}
	
	public static PrivateKey getPrivateKey(String textFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		Path file = Paths.get(textFile + ".txt");
		byte[] privKey = Files.readAllBytes(file);
		PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privKey));
		
		return privateKey;
	}
	
	public static void storePublicKey(PublicKey publicKey, String textFile) throws IOException {
		byte[] publicKeybytes = publicKey.getEncoded();
		
		File newFile = new File(textFile + "Pub.txt");
		FileOutputStream fop = new FileOutputStream(newFile);
		fop.write(publicKeybytes);
		fop.close();
	}
	
	public static PublicKey getPublicKey(String textFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		Path file = Paths.get(textFile + "Pub.txt");
		byte[] pubKey = Files.readAllBytes(file);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKey));
		
		return publicKey;
	}
	
	public static KeyPair generateKeyPair(int bits) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(bits, new SecureRandom());
		KeyPair pair = generator.generateKeyPair();
		
		return pair;
	}

	public static String Sign(String plaintext, PrivateKey privatekey) throws Exception {
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privatekey);
		privateSignature.update(plaintext.getBytes("UTF-8"));
		
		byte[] signature = privateSignature.sign();
		
		String signature_str = Base64.getEncoder().encodeToString(signature);
		
		return signature_str;
	}
	
	public static boolean verify(String plaintext, String signature, PublicKey publickey) throws Exception {
		Signature publicsignature = Signature.getInstance("SHA256withRSA");
		publicsignature.initVerify(publickey);
		publicsignature.update(plaintext.getBytes("UTF-8"));
		
		byte[] signatureBytes = Base64.getDecoder().decode(signature);
		
		return publicsignature.verify(signatureBytes);
	}

}
