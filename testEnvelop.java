package ks.test;
import org.junit.Test;

import ks.API.EncryptAPI;

public class testEnvelop {
	private static EncryptAPI ea = new EncryptAPI();
	
	@Test
	public void testEnvelopEncrypt() throws Exception {
		String pk = "A3744F18DE4E4A1A04C0679BE6C62ED43A6676BB5E9136FBDBB1B6072544AC9D0DAD2742D2605271B6A374894C6E71EAD2F54CBE44B4BFA60C3D1535E130D377";
		String data = "你好你好你好你好你好你好你好}}!@!#!#@";
		
		String[] env = ea.encryptData_Envelop(pk, data);
		String keyByPK = env[0];
		String encData = env[1];
		
		System.out.println("公钥加密的SM4密钥为: ["+keyByPK+"]");
		System.out.println("SM4密钥加密的数据为: ["+encData+"]");
	}
	
	@Test
	public void testEnvelopDecrypt() throws Exception {
		String vk = "33FDAAFD858B3246A73997AB91DD6AAF6729E0B8E9778906F1CEF97D6CCB5F93";
		String encData = "6D766A32A9DC75A1C92F2F09497662A80C0289E7FFFAE23449F3B5DF5D4B6BED110DBB4F83B9CB16B8AB241A95D8C31E";
		String keyByPK = "E599D7F55E16F7A53C5744CD993FE3A826FFB69B433B972B184D79173E3F6A0C221518EC1AEBEB48384C33E1D89877CDDCFA062B8CADFFF7131F6F74FF7C44528B0478676FBFB8E10798EDF97C3C4C3B63AE1F9B569E6EEC7409FE7FA458CF59D3AADF083C8001229B547E650B7DBC87";
		
		String[] env = ea.decryptData_Envelop(vk, keyByPK, encData);
		
		String sm4Key = env[0];
		String plainData = env[1];
		
		System.out.println("SM4密钥明文为：["+sm4Key+"]");
		System.out.println("数据明文为：["+plainData+"]");
	}
}
