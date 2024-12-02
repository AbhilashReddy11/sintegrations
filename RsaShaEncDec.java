package in.gov.enam.integrations.util;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;
@Component
public class RsaShaEncDec {
	
	
	public static final int SALT_LENGTH_BYTE = 16;
	public static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
	public static final int TAG_LENGTH_BIT = 128;
	public static final int IV_LENGTH_BYTE = 12;
	public static final int AES_KEY_BIT = 256; 

	
//	public String getAlphaNumericString(int n) throws Exception {
//		String os = System.getProperty("os.name").toLowerCase();
//		SecureRandom sr = null;
//		if (os.indexOf("win") >= 0) {
//				sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
//			} else {
//				sr = SecureRandom.getInstance("SHA1PRNG", "IBMJCE");
//			}
//		   byte[] randomBytes = new byte[128];
//		   sr.nextBytes(randomBytes);
//		   String randomString = new String(randomBytes, Charset.forName("UTF-8"));
//		   StringBuffer r = new StringBuffer();
//		   for (int k = 0; k < randomString.length(); k++) {
//		   char ch = randomString.charAt(k);
//		   if (((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) && (n > 0)) {
//		   r.append(ch);
//		   n--;
//		}
//	   }
//	return r.toString();
//	}
	public String getAlphaNumericString(int n) {
	    SecureRandom sr = new SecureRandom();
	    String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	    StringBuilder result = new StringBuilder(n);

	    for (int i = 0; i < n; i++) {
	        int index = sr.nextInt(characters.length());
	        result.append(characters.charAt(index));
	    }

	    return result.toString();
	}

	
		
	public byte[] getRandomNonce(int numBytes) {
	        byte[] nonce = new byte[numBytes];
	        new SecureRandom().nextBytes(nonce);
	        return nonce;
	    }
	
	public String encryptAES(String data, String sessionKey) throws Exception {
		   // 16 bytes salt
					byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);


					// GCM recommended 12 bytes iv?
					byte[] iv = getRandomNonce(IV_LENGTH_BYTE);


					/* Create factory for secret keys. */  
					SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  


					/* PBEKeySpec class implements KeySpec interface. */  
					KeySpec spec = new PBEKeySpec(sessionKey.toCharArray(), salt, 65536, AES_KEY_BIT);
					SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
					Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
					cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
					byte[] cipherText = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));


					// prefix IV and Salt to cipher text
					byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
							.put(iv)
							.put(salt)
							.put(cipherText)
							.array();


					// string representation, base64, send this string to other for decryption.
					return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
		}

	
	public String generateSign(String data, String privateKeyPath, String privateKeyPassword) throws Exception {
		Signature sign = Signature.getInstance("SHA256withRSA");
		PrivateKey privateKey = getPrivateKey(privateKeyPath);
		sign.initSign(privateKey);
		byte[] bytes = data.getBytes(Charset.forName("UTF-8"));
		sign.update(bytes);
		byte[] signature = sign.sign();
		String result = Base64.getEncoder().encodeToString(signature);
		return result;
		}
	public String generateSign(String data, String privateKeyPath) throws Exception {
		Signature sign = Signature.getInstance("SHA256withRSA");
	//	PrivateKey privateKey = getPrivateKey(privateKeyPath);
		PrivateKey privateKey = readPrivateKeyFromPem(privateKeyPath);
		sign.initSign(privateKey);
		byte[] bytes = data.getBytes(Charset.forName("UTF-8"));
		sign.update(bytes);
		byte[] signature = sign.sign();
		String result = Base64.getEncoder().encodeToString(signature);
		return result;
		}
	
	public boolean verifySign(String data, String hashValue, String publicKeyPath) throws Exception {
	    byte[] signature = Base64.getDecoder().decode(hashValue);
	    Signature sign = Signature.getInstance("SHA256withRSA");
	    PublicKey publicKey = getPublicKey(publicKeyPath);
	    sign.initVerify(publicKey);
	    sign.update(data.getBytes(Charset.forName("UTF-8")));
	    boolean bool = sign.verify(signature);
	    return bool;
	}
	public PublicKey getPublicKey(String publicKeyPath) throws Exception {
		FileInputStream fin = null;
		PublicKey publicKey = null;
		try {
			fin = new FileInputStream(publicKeyPath);
			CertificateFactory f = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate)f.generateCertificate(fin);
			publicKey = certificate.getPublicKey();
		} catch (Exception exp) {
			exp.printStackTrace();
		} 
		return publicKey;
}
//	public PublicKey getPublicKey(String publicKeyPath) throws Exception {
//	    // Read all bytes from the file
//	    String key = new String(Files.readAllBytes(Paths.get(publicKeyPath)))
//	            .replaceAll("-----BEGIN PUBLIC KEY-----", "")
//	            .replaceAll("-----END PUBLIC KEY-----", "")
//	            .replaceAll("\\s", "");
//
//	    // Decode the base64 encoded string
//	    byte[] keyBytes = Base64.getDecoder().decode(key);
//
//	    // Create the public key using KeyFactory
//	    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
//	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//	    return keyFactory.generatePublic(keySpec);
//	}



	public String decryptRSA(String encryptedKey, String privateKeyPath) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		byte[] bytes = Base64.getDecoder().decode(encryptedKey);
		Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		PrivateKey privateKey;
				
		String extention = Optional.ofNullable(privateKeyPath).filter(f -> f.contains(".")).map(f -> f.substring(privateKeyPath.lastIndexOf(".") + 1)).get();
		if("pem".equalsIgnoreCase(extention)) {
			privateKey = readPrivateKeyFromPem(privateKeyPath);
		}else {
			privateKey = getPrivateKey(privateKeyPath);
		}
				
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		String result = new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
		return result;
	}


	public PrivateKey readPrivateKeyFromPem(String filename) throws Exception {
		File file = new File(filename);
		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());


		String privateKeyPEM = key
		  .replace("-----BEGIN PRIVATE KEY-----", "")
		  .replaceAll(System.lineSeparator(), "")
		  .replace("-----END PRIVATE KEY-----", "");


		byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);


		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		return keyFactory.generatePrivate(keySpec);
	}

//	public PrivateKey getPrivateKey(String filename) throws Exception {
//		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
//		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//		return keyFactory.generatePrivate(keySpec);
//	}
//	public PrivateKey getPrivateKey(String filename) throws Exception {
//        String keyContent = readKeyFile(filename);
//        
//        // Remove the "-----BEGIN RSA PRIVATE KEY-----" and "-----END RSA PRIVATE KEY-----" lines
//        keyContent = keyContent
//                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
//                .replace("-----END RSA PRIVATE KEY-----", "")
//                .replaceAll("[\\r\\n\\s]", ""); // Remove all whitespace characters
//
//        // Decode the Base64 content
//        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
//
//        // Generate private key
//        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        return keyFactory.generatePrivate(keySpec);
//    }
//
//    private String readKeyFile(String filename) throws IOException {
//        StringBuilder keyContent = new StringBuilder();
//        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
//            String line;
//            while ((line = reader.readLine()) != null) {
//                keyContent.append(line).append("\n");
//            }
//        }
//        return keyContent.toString();
//    }
	public PrivateKey getPrivateKey(String filename) throws Exception {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}



	private byte[] readFileBytes(String filename) throws Exception {
		Path path = Paths.get(filename, new String[0]);
		return Files.readAllBytes(path);
	}


	public String decryptAES (String encryptedTokenRequest, String sessionKey) throws Exception {    
		ByteBuffer bb = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedTokenRequest));


		byte[] iv = new byte[IV_LENGTH_BYTE];
		bb.get(iv);


		byte[] salt = new byte[SALT_LENGTH_BYTE];
		bb.get(salt);


		byte[] cipherText = new byte[bb.remaining()];
		bb.get(cipherText);
		
		/* Create factory for secret keys. */  
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");  


		/* PBEKeySpec class implements KeySpec interface. */  
		KeySpec spec = new PBEKeySpec(sessionKey.toCharArray(), salt, 65536, AES_KEY_BIT);
		SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
		
		Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cipherText);
		
        return new String(plainText);
}
	public String encryptRSA(String plaintext, String publicKey) throws Exception {
		   Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		   Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
		   PublicKey publicKeyObj = getPublicKey(publicKey);
		   cipher.init(Cipher.ENCRYPT_MODE, publicKeyObj);
		   byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
		   String result = Base64.getEncoder().encodeToString(cipherText);
		   return result;
		}

	

}
