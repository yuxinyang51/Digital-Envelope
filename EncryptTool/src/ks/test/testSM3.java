package ks.test;
import org.junit.Test;

import ks.API.EncryptAPI;

public class testSM3 {
	private static EncryptAPI ea = new EncryptAPI();
	
	@Test
	public void testSM3() {
		String digest = ea.SM3("123");
		System.out.println("摘要为: ["+digest+"]");
	}
}
