package ks.API;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.text.DecimalFormat;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;

import ks.utils.SM2Result;
import ks.sm.*;
import ks.utils.Cipher;
import ks.utils.SM2Utils;
import ks.utils.SM3Digest;
import ks.utils.Util;


public class EncryptAPI {
	private static SM2 sm2 = new SM2();
	private static SM3Digest sm3 = new SM3Digest();
	private static SM4 sm4 = new SM4();
	private static Util util = new Util();
	private static DecimalFormat df=new DecimalFormat("0000");
	
/*
 * 功能：随机生成密钥对
 * 入参: Null
 * 返回: String[] 
 */
	public static String[] generateKeyPair(){
		String[] keyPair = new String[2];
		
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		String pk = Util.byteToHex(publicKey.getEncoded()).substring(2, Util.byteToHex(publicKey.getEncoded()).length());
//		String vk = Util.byteToHex(privateKey.toByteArray()).substring(2, Util.byteToHex(privateKey.toByteArray()).length());
		String vk = Util.byteToHex(privateKey.toByteArray());
		
		if (vk.length() != 64 && vk.length() == 66 && vk.substring(0,2).equals("00")) {
			vk = vk.substring(2, vk.length());
		} else if(vk.length() == 64) {

		} else {
			System.out.println("生成密钥对异常");
			System.out.println("vk "+vk);
			System.out.println("pk "+pk);
		}
		keyPair[0] = pk;
		keyPair[1] = vk;
		
		return keyPair;	
	}

/*
 * 功能：公钥加密(C1C2C3模式)
 * 入参：String publicKey, String data
 * 返回: String encData
 */
	public static String encryptByPK1(String publicKey, String data) throws IOException
	{
		 if (publicKey == null || publicKey.length() == 0)
	        {
	            return null;
	        }

	        if (data == null || data.length() == 0)
	        {
	            return null;
	        }
	        publicKey = "04"+publicKey;
	        byte[] publicKeyBytes = ByteUtils.fromHexString(publicKey);
	        byte[] plainTextBytes = ByteUtils.fromHexString(data);
	        byte[] source = new byte[plainTextBytes.length];
	        System.arraycopy(plainTextBytes, 0, source, 0, plainTextBytes.length);

//	        source = data.getBytes();

	        Cipher cipher = new Cipher();
	//  SM2 sm2 = new SM2();
	        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKeyBytes);

	        ECPoint c1 = cipher.Init_enc(sm2, userKey);
	        cipher.Encrypt(source);
	        byte[] c3 = new byte[32];
	        cipher.Dofinal(c3);
	        String C1 = Util.byteToHex(c1.getEncoded());
	        String C2 = Util.byteToHex(source);
	        String C3 = Util.byteToHex(c3);
	        String encData = C1+C2+C3;
	        //C1 C2 C3拼装成加密字串
	        return encData.substring(2,encData.length());
	}

/*
 * 功能：公钥加密(C1C3C2模式)
 * 入参：String publicKey, String data
 * 返回: 
 */
	public static String encryptByPK2(String publicKey, String data) throws IOException{
		if (publicKey == null || publicKey.length() == 0){
			return null;
		} 
			
		if (data == null || data.length() == 0){
			return null;
		}
			
		byte[] source = new byte[data.length()];
//		System.arraycopy(data, 0, source, 0, data.length());
		source = data.getBytes();
			
		Cipher cipher = new Cipher();
//		SM2 sm2 = new SM2();
		publicKey = "04"+publicKey;
		ECPoint userKey = sm2.ecc_curve.decodePoint(Util.hexToByte(publicKey));
			
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		String C1 = Util.byteToHex(c1.getEncoded());
		String C2 = Util.byteToHex(source);
		String C3 = Util.byteToHex(c3);
		String encData = C1+C3+C2;
		//C1 C3 C2拼装成加密字串
		return encData.substring(2,encData.length());
		}
	
/*
 * 功能：私钥解密 C1C2C3
 * 入参：String privateKey , String encryptedData
 * 返回：String plainData
 */
	public static String decryptByVK1(String privateKey, String encryptedData) throws IOException
	{
		if (privateKey == null || privateKey.length() == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length() == 0)
		{
			return null;
		}
		//加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		
//		String data = Util.byteToHex(encryptedData.getBytes());
		String data = "04"+encryptedData;
//		System.out.println("Data="+data);
		/***分解加密字串
		 * （C1 = C1标志位2位 + C1实体部分128位 = 130）
		 * （C3 = C3实体部分64位  = 64）
		 * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
		int c2Len = Util.hexToByte(data).length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
		
//		SM2 sm2 = new SM2();
		BigInteger userD = new BigInteger(1, Util.hexToByte(privateKey));
		
		//通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		String plainData = Util.byteToHex(c2);
		//返回解密结果
		return plainData;
	}

/*
 * 功能：私钥解密 C1C3C2
 * 入参：String privateKey , String encryptedData
 * 返回：String plainData
 */
	public static String decryptByVK2(String privateKey, String encryptedData) throws IOException
	{
		if (privateKey == null || privateKey.length() == 0)
		{
			return null;
		}
		
		if (encryptedData == null || encryptedData.length() == 0)
		{
			return null;
		}
		String C1 = encryptedData.substring(0,128);
		String C3 = encryptedData.substring(128,192);
		String C2 = encryptedData.substring(192,encryptedData.length());

		//加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
		String data = "04"+C1+C2+C3;
		System.out.println("Data="+data);
		/***分解加密字串
		 * （C1 = C1标志位2位 + C1实体部分128位 = 130）
		 * （C3 = C3实体部分64位  = 64）
		 * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
		 */
		byte[] c1Bytes = Util.hexToByte(data.substring(0,130));
		int c2Len = Util.hexToByte(data).length - 97;
		byte[] c2 = Util.hexToByte(data.substring(130,130 + 2 * c2Len));
		byte[] c3 = Util.hexToByte(data.substring(130 + 2 * c2Len,194 + 2 * c2Len));
		
//			SM2 sm2 = new SM2();
		BigInteger userD = new BigInteger(1, Util.hexToByte(privateKey));
		
		//通过C1实体字节来生成ECPoint
		ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		String plainData = Util.byteToHex(c2);
		//返回解密结果
		return plainData;
	}
	
	public static String SM3(String data) {
		String digest = "";
		byte[] md = new byte[32];
		byte[] msg1 = data.getBytes();
		sm3.update(msg1, 0, msg1.length);
		sm3.doFinal(md, 0);
		String s = new String(Hex.encode(md));
		digest = s.toUpperCase();
		
		return digest;
	}
	
    /**
     * 签名
     * @param privateKey 签名私钥
     * @param plainText 明文
     * @return
     */
	public static String sign(String privateKey,String signData) {
		String sign = "";
		
		return sign;
	}
	
    /**
     * SM4_ECB           加密
     * @param key        密钥明文
     * @param data       数据明文
     * @return encData   数据密文
     */
	public static String encrypt_SM4_ecb(String key,String data) {
		String encData = "";
		String sm4Key = key;
		String plainData = data;
		
		try {
			encData = sm4.encrypt_ECB(sm4Key, plainData);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return encData;
	}
	
    /**
     * SM4_ECB 			解密
     * @param key	    密钥明文
     * @param data      数据密文
     * @return encData  数据明文
     */
	public static String decrypt_SM4_ecb(String key,String encData) {
		if(key == "" || key.length()!=32) {
			System.out.println("密钥错");
		}
		if(encData == "") {
			System.out.println("输入数据错");
		}
		
		String plainData = "";
		String sm4Key = key;
		String data = encData;
		
		try {
			plainData = sm4.decrypt_ECB(sm4Key, data);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return plainData;
	}
	
    /**
     * encryptData_Envelop 数字信封加密
     * @param pkValue      公钥值
     * @param data    	   待加密的数据明文
     * @return envelop     数据信封(含sm4密钥密文、数据密文)
     */
	public static String[] encryptData_Envelop(String pkValue, String data) throws Exception {
		if (pkValue == null || pkValue.length() == 0)
		{
			return null;
		}
		if (data == null || data.length() == 0)
		{
			return null;
		}
		
		String[] envelop = new String[2];
//		String tmpData = df.format(data.length())+data;
		
		//将tmpData转为Hex
		String hexData = util.asciiToHex(data);
		String tmpData = util.asciiToHex(df.format(hexData.length()/2))+hexData;
		
//		int length =hexData.getBytes("gb2312").length;
		int length = tmpData.getBytes("gb18030").length;
		
		//数据长度+数据明文+填充0 直至总长度为32的倍数，组成tmpData。
		if(length%32 != 0) {
			int numOfzero = 32 - length%32;
			for (int i=0;i<numOfzero/2;i++) {
				tmpData = tmpData+"30";
			}
		} 
		hexData = tmpData;
		
		//1.随机生成SM4密钥
		String sm4Key = sm4.generateKey();
		System.out.println(sm4Key);
		//2.公钥加密SM4密钥
		String keyByPK = encryptByPK1(pkValue, sm4Key);
		//3.SM4密钥加密数据明文
		System.out.println("hexData:" + hexData);
		String encData = sm4.encrypt_ECB(sm4Key, hexData.toUpperCase());
		
		envelop[0] = keyByPK;
		envelop[1] = encData;
		
		return envelop;
	}
	
    /**
     * encryptData_Envelop 数字信封解密
     * @param vk      	   私钥值
     * @param keyByPK      公钥加密的sm4Key
     * @return envelop     数据信封(含sm4密钥明文、数据明文)
     */
	public static String[] decryptData_Envelop(String vk, String keyByPK, String encData) throws Exception {
		String[] envelop = new String[2];
		
//		String sm4Key = Util.hexToAscii(decryptByVK1(vk, keyByPK));
		//私钥解密SM4对称密钥
		String sm4Key = decryptByVK1(vk, keyByPK);
		//SM4算法解密数据，得到的是4字节填充+hex数据+30填充
		String plainData = sm4.decrypt_ECB(sm4Key, encData).toUpperCase();
		
		//去填充，得到明文
		int lenOfdata = Integer.parseInt(util.hexToAscii(plainData.substring(0, 8)));
		String hexData = plainData.substring(8, 8+lenOfdata*2);
		String ascData = new String(util.hexStringToBytes(hexData), "gb18030");
		
		envelop[0] = sm4Key;
		envelop[1] = ascData;
		
		return envelop;
	}
	
    /**
     * signWithSM3         私钥签名
     * @param data 	 	   待签名数据
     * @param vk      	   私钥明文
     * @param userID       sm3签名时的userID
     * @return sign        签名
     */
	public static String signWithSm3(String data, String vk, String userID) throws IOException {
		String sign = "";
		byte[] privateKey = Hex.decode(vk);
		byte[] sourceData = data.getBytes();
		byte[] userId = userID.getBytes();
		
       if (privateKey != null && privateKey.length != 0) {
            if (sourceData != null && sourceData.length != 0) {
                BigInteger userD = new BigInteger(privateKey);
                org.bouncycastle.math.ec.ECPoint userKey = sm2.ecc_point_g.multiply(userD);
                byte[] z = sm2.sm2GetZ(userId, userKey);
                SM3Digest sm3 = new SM3Digest();
                sm3.update(z, 0, z.length);
                sm3.update(sourceData, 0, sourceData.length);
                byte[] md = new byte[32];
                sm3.doFinal(md, 0);
                SM2Result sm2Result = new SM2Result();
                sm2.sm2Sign(md, userD, userKey, sm2Result);
                DERInteger d_r = new DERInteger(sm2Result.r);
                DERInteger d_s = new DERInteger(sm2Result.s);
                ASN1EncodableVector v2 = new ASN1EncodableVector();
                v2.add(d_r);
                v2.add(d_s);
                DERSequence signTmp = new DERSequence(v2);
                byte[] signdata = signTmp.getEncoded();
                sign = util.byteToHex(util.convertDERSign(signdata));
        		return sign;
//                return signdata;
            } else {
                return null;
            }
        } else {
            return null;
        }
	}
	
	public static String encryptByPKforKS(String publicKey, byte[] data) throws IOException
	{
		if (publicKey == null || publicKey.length() == 0)
		{
			return null;
		} 
		
		if (data == null || data.length == 0)
		{
			return null;
		}
		
		byte[] source = new byte[data.length];
//		System.arraycopy(data, 0, source, 0, data.length());
		
		Cipher cipher = new Cipher();
//		SM2 sm2 = new SM2();
		publicKey = "04"+publicKey;
		ECPoint userKey = sm2.ecc_curve.decodePoint(Util.hexToByte(publicKey));
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		String C1 = Util.byteToHex(c1.getEncoded());
		String C2 = Util.byteToHex(source);
		String C3 = Util.byteToHex(c3);
		String encData = C1+C2+C3;
		//C1 C2 C3拼装成加密字串
		return encData.substring(2,encData.length());
	}
	
	public static String encryptByPKforks(String publicKey, String data) throws IOException
    {
        if (publicKey == null || publicKey.length() == 0)
        {
            return null;
        }

        if (data == null || data.length() == 0)
        {
            return null;
        }
        publicKey = "04"+publicKey;
        byte[] publicKeyBytes = ByteUtils.fromHexString(publicKey);
        byte[] plainTextBytes = ByteUtils.fromHexString(data);
        byte[] source = new byte[plainTextBytes.length];
        System.arraycopy(plainTextBytes, 0, source, 0, plainTextBytes.length);

//        source = data.getBytes();

        Cipher cipher = new Cipher();
//  SM2 sm2 = new SM2();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKeyBytes);

        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte[] c3 = new byte[32];
        cipher.Dofinal(c3);
        String C1 = Util.byteToHex(c1.getEncoded());
        String C2 = Util.byteToHex(source);
        String C3 = Util.byteToHex(c3);
        String encData = C1+C2+C3;
        //C1 C2 C3拼装成加密字串
        return encData.substring(2,encData.length());
    }
	
//	public static void main(String[] args) throws Exception {
//        String plainText = "你好啊，朋友";
//        System.out.println("原数据: "+plainText);
//        String privateKey = "50A3D99ADBAA245671257EDA9D859780E49440044488D70F7EE083984D0C13C6";
//        //测试用户
//        String userId = "9001@qq.COM";
//        //签名
//        String sign = signWithSm3(plainText, privateKey, userId);
//        System.out.println(sign);
//	}

}
