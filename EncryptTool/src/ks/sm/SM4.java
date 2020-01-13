package ks.sm;


import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import ks.utils.SM4Util;
import ks.utils.Util;

public class SM4 {
	private static SM4Util util = new SM4Util();
	private static Util util1 = new Util();


	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
//	private static final String ENCODING = "UTF-8";
	private static final String ENCODING = "gb18030";
	public static final String ALGORITHM_NAME = "SM4";
	
	public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/NOPADDING";
	public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/NOPADDING";
	public static final int DEFAULT_KEY_SIZE = 128;
	
	/**
	 * 生成ECB暗号
	 * @explain ECB模式
	 * 			算法名称
	 * @param mode
	 * 			模式
	 * @param key
	 * @return
	 * @throws Exception
	 */
	private static Cipher generateEcbCipher(String algoritmName, int mode, byte[] key) throws Exception{
		Cipher cipher = Cipher.getInstance(algoritmName, BouncyCastleProvider.PROVIDER_NAME);
		Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
		cipher.init(mode, sm4Key);
		return cipher;
	}
	
	private static Cipher generateCbcCipher(String algoritmName, int mode, byte[] key, byte[] iv) throws Exception{
		Cipher cipher = Cipher.getInstance(algoritmName, BouncyCastleProvider.PROVIDER_NAME);
		Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
		IvParameterSpec ivparam = new IvParameterSpec(iv);
		
		cipher.init(mode, sm4Key, ivparam);
		return cipher;
	}
	
	public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data) throws Exception {
		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(data);
	}

	public static byte[] encrypt_cbc_Padding(byte[] key, byte[] data, byte[] iv) throws Exception {
		Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, key, iv);
		return cipher.doFinal(data);
	}
	
	/**
	 * 随机生成SM4密钥
	 * @param 
	 * @return String key   
	 * @throws Exception
	 */
	public static String generateKey() throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);
		kg.init(128, new SecureRandom());
		String key = Hex.toHexString(kg.generateKey().getEncoded()).toUpperCase();
		return key;
	}
	
	/**
	 * SM4 加密，ECB模式
	 * @param String hexKey  密钥
	 * @param String data  待加密数据明文
	 * @return String  copherText  数据密文
	 * @throws Exception
	 */
	public static String encrypt_ECB(String hexKey, String data) throws Exception {
		String encData = "";
		
		byte[] keyData = ByteUtils.fromHexString(hexKey);
//		byte[] srcData = util.hexToAscii(data).getBytes(ENCODING);
		byte[] srcData = util1.hexStringToBytes(data);
		Key sm4Key = new SecretKeySpec(keyData, ALGORITHM_NAME);
		
		Cipher cp = Cipher.getInstance("SM4/ECB/NOPADDING", BouncyCastleProvider.PROVIDER_NAME);
		
		cp.init(Cipher.ENCRYPT_MODE, sm4Key);
		byte[] encDataArray = cp.doFinal(srcData);
		encData = ByteUtils.toHexString(encDataArray).toUpperCase();
		
		return encData;
	}
	
	public static String decrypt_ECB(String hexKey, String cipherText) throws Exception {
		String plainData = "";
		byte[] keyData = ByteUtils.fromHexString(hexKey);
//		byte[] cipherData = ByteUtils.fromHexString(cipherText);
		byte[] cipherData = util1.hexStringToBytes(cipherText);
		
		Cipher cipher = Cipher.getInstance("SM4/ECB/NOPADDING", BouncyCastleProvider.PROVIDER_NAME);
		Key sm4Key = new SecretKeySpec(keyData, ALGORITHM_NAME);
		cipher.init(Cipher.DECRYPT_MODE, sm4Key);
		byte[] srcData = cipher.doFinal(cipherData);
//		Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
//		byte[] srcData = decrypt_Ecb_Padding(keyData, cipherData);
//		plainData = util.asciiToHex(new String(srcData, ENCODING));
		plainData = ByteUtils.toHexString(srcData).toUpperCase();
		
		return plainData;
	}
	
	public static String encrypt_CBC_SM4(String hexKey, String data, String iv) throws Exception {
		String cipherText = "";
		
		byte[] keyData = ByteUtils.fromHexString(hexKey);
		byte[] srcData = util.hexToAscii(data).getBytes(ENCODING);
		byte[] srcIv = iv.getBytes();
		
		byte[] cipherArray = encrypt_cbc_Padding(keyData, srcData, srcIv);
		cipherText = ByteUtils.toHexString(cipherArray).toUpperCase();

		return cipherText;
	}
	
	public static String encrypt_CBC(String hexKey, String data, String iv) throws Exception {
		String cipherText = "";
		
		Key keyData = new SecretKeySpec(hexKey.getBytes(), ALGORITHM_NAME);
		byte[] srcData = util.hexToAscii(data).getBytes(ENCODING);
		byte[] srcIv = iv.getBytes();
		
		IvParameterSpec ivparam = new IvParameterSpec(srcIv);
		Cipher cp = Cipher.getInstance("SM4/CBC/NOPADDING");
		cp.init(Cipher.ENCRYPT_MODE, keyData, ivparam);
		
		return cipherText;
	}
	
	public static void main(String[] args) throws Exception {
//		String data = decrypt_ECB("3BBAF7F6ABF4053994AF33F8CDE9E294","5A32F5B6DAAC013D2AF328DE87097885");
		String data = encrypt_ECB("3BBAF7F6ABF4053994AF33F8CDE9E294","12345678123456781234567812345678");
//		String data = encrypt_CBC("3BBAF7F6ABF4053994AF33F8CDE9E294","12345678123456781234567812345678", "12345678123456781234567812345678");

		System.out.println("data: "+data);
	}

}
