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
		/** RSA�㷨Ҫ����һ�������ε������Դ */
		SecureRandom secureRandom = new SecureRandom();

		/** ΪRSA�㷨����һ��KeyPairGenerator���� */
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);

		/** ����������������Դ��ʼ�����KeyPairGenerator���� */
		keyPairGenerator.initialize(KEYSIZE, secureRandom);

		/** �����ܳ׶� */
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		/** ���ɹ�Կ **/
		publicKey = (RSAPublicKey) keyPair.getPublic();

		/** ����˽Կ **/
		privateKey = (RSAPrivateKey) keyPair.getPrivate();

		/**���ָ����ģ**/
		modulus = publicKey.getModulus();
		publicExponent = publicKey.getPublicExponent();
		privateExponent = privateKey.getPrivateExponent();
		
		/**���ɱ��ر���*/
		publicKeyByte = publicKey.getEncoded();
		privateKeyByte = privateKey.getEncoded();
		
		/** ����base64���� **/
		publicKeyString = Base64.getEncoder().encodeToString(publicKeyByte);
		privateKeyString = Base64.getEncoder().encodeToString(privateKeyByte);
		
		// /**������д���ļ���**/
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
	 * ͨ��ָ����ģ�����ɹ�Կ
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
	 * ͨ��ָ����ģ������˽Կ
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
	 * ͨ��byte���뻹ԭ��Կ
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
	 * ͨ��byte���뻹ԭ˽Կ
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
	
	/** ���� **/
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

	/** ���� **/
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
