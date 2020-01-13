package ks.test;

import org.junit.Test;
import ks.API.EncryptAPI;

public class testSM4 {
	
	private static EncryptAPI ea = new EncryptAPI();
	
	@Test
	public void testEncrypt_SM4_ecb() {
		String key = "D6D2BB7CDA9D45F37C5D73307DA61F42";
		String data = "303033323132333435363738313233343536373831323334353637383132333435363738303030303030303030303030";
		
		String encData = ea.encrypt_SM4_ecb(key, data);
		System.out.println("SM4_ECB 加密结果为: ["+encData+"]");
	}
	
	@Test
	public void testDecrypt_SM4_ecb() {
		String key = "47AF0FE5FFB56887B2B7103181779EF0";
		String data = "348C9D6973DFD0B64E88924AAEAA3845";
		
		String plainData = ea.decrypt_SM4_ecb(key, data);
		System.out.println("SM4_ECB_ 解密结果为: ["+plainData+"]");
	}
}
