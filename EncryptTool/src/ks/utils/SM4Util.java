package ks.utils;

import java.security.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;


public class SM4Util {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	private static final String ENCODING = "UTF-8";
	public static final String ALGORITHM_NAME = "SM4";
	
	public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5PADDING";
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
	
	public static byte[] generateKey(int size) throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);
		kg.init(128, new SecureRandom());
		return kg.generateKey().getEncoded();
	}
	
	public static String hexToAscii(String hexStr) {
		StringBuilder output = new StringBuilder("");
		for (int i = 0; i < hexStr.length(); i += 2) {
		String str = hexStr.substring(i, i + 2);
		output.append((char) Integer.parseInt(str, 16));
		}
		return output.toString();
	}
	
	public static String asciiToHex(String asciiStr) {
		char[] chars = asciiStr.toCharArray();
		StringBuilder hex = new StringBuilder();
		for (char ch : chars) {
		hex.append(Integer.toHexString((int) ch));
		}
		return hex.toString();
	}
	
	public static void main(String[] args) throws Exception {
		byte[] b = generateKey(128);
		System.out.println(Hex.toHexString(b).toUpperCase());
	}
}
