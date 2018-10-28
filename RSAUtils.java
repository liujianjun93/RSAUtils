package encrypt;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAUtils {
	public static final String ALGORITHM = "RSA";
	public static final int KEYSIZE = 1024;
	private RSAPrivateKey privateKey;
	private RSAPublicKey publicKey;
	private BigInteger modulus;
	private BigInteger publicExponent;
	private BigInteger privateExponent;
	private byte[] publicKeyByte;
	private byte[] privateKeyByte;
	private String publicKeyString;
	private String privateKeyString;
	

	public void generateKey() throws NoSuchAlgorithmException, IOException {
		/** RSA算法要求有一个可信任的随机数源 */
		SecureRandom secureRandom = new SecureRandom();

		/** 为RSA算法创建一个KeyPairGenerator对象 */
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

		/** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
		keyPairGenerator.initialize(KEYSIZE, secureRandom);

		/** 生成密匙对 */
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		/** 生成公钥 **/
		publicKey = (RSAPublicKey) keyPair.getPublic();

		/** 生成私钥 **/
		privateKey = (RSAPrivateKey) keyPair.getPrivate();

		/**获得指数和模**/
		modulus = publicKey.getModulus();
		publicExponent = publicKey.getPublicExponent();
		privateExponent = privateKey.getPrivateExponent();
		
		/**生成比特编码*/
		publicKeyByte = publicKey.getEncoded();
		privateKeyByte = privateKey.getEncoded();
		
		/** 生成base64编码 **/
		publicKeyString = Base64.getEncoder().encodeToString(publicKeyByte);
		privateKeyString = Base64.getEncoder().encodeToString(privateKeyByte);
		
		// /**将编码写入文件中**/
		// String pulicKeyFilePath = " ";
		// String privateKeyFilePath = " ";
		//
		// FileWriter pubfw = new FileWriter(pulicKeyFilePath);
		// BufferedWriter pubbw = new BufferedWriter(pubfw);
		// pubbw.write(publicKeyString);
		// pubbw.flush();
		// pubbw.close();
		// pubfw.close();
		// System.out.println("modulus :"+modulus);
		// System.out.println("exponet :"+e);
	}

	/**
	 * 通过指数和模来生成公钥
	 **/
	public RSAPublicKey generatePublicKeyByModulsAndExponent(BigInteger modulus,BigInteger publicExponent) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus,publicExponent);
		    RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(rsaPublicKeySpec);
		    return publicKey;
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 通过指数和模来生成私钥
	 **/
	public RSAPrivateKey generatePrivateKeyByModulsAndExponent(BigInteger modulus,BigInteger privateExponent) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus,privateExponent);
		    RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(rsaPrivateKeySpec);
		    return privateKey;
		}catch(Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	
	/**
	 * 通过byte编码还原公钥
	 */
	public RSAPublicKey generatePublicKeyByByteArray(byte[] publicKeyData) {
		try {
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(keySpec);
			return publicKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 通过byte编码还原私钥
	 */
	public RSAPrivateKey generatePrivateKeyByByteArray(byte[] privateKeyData) {
		try {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyData);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpec);
			return privateKey;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/** 加密 **/
	public byte[] encrypt(RSAPublicKey publicKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] output = cipher.doFinal(data);
			return output;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/** 解密 **/
	public byte[] decrypt(RSAPrivateKey privateKey, byte[] data) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] output = cipher.doFinal(data);
			return output;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
