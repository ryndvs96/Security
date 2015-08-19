package rsa;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private BigInteger n, d, e;
	private int bitlen = 1024;
	public RSA(BigInteger n, BigInteger e) {
		this.n = n;
		this.e = e;
	}
	public RSA(int bitlen) {
		this.bitlen = bitlen;
		generateKeys();
	}
	public synchronized void generateKeys() {
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 100, r);
		BigInteger q = new BigInteger(bitlen / 2, 100, r);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}
	public synchronized String encrypt(String message) {
		String cipherText = new String((new BigInteger(message)).modPow(e, n).toByteArray());
		return cipherText;
	}
	public synchronized BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}
	public synchronized String decrypt(String message) {
		String cipherText = new String((new BigInteger(message)).modPow(d, n).toByteArray());
		return cipherText;
	}
	public synchronized BigInteger decrypt(BigInteger message) {
		return message.modPow(d, n);
	}
	public synchronized BigInteger getN() {
		return n;
	}
	public synchronized BigInteger getE() {
		return e;
	}
	
	public static void main(String[] args) {
		RSA rsa = new RSA(1024);
		
		String textInput = "This message is to be encrypted";
		System.out.println("input text: " + textInput);
		BigInteger plainText = new BigInteger(textInput.getBytes());
		
		BigInteger cipherText = rsa.encrypt(plainText);
		System.out.println("cipher text: " + cipherText);
		plainText = rsa.decrypt(cipherText);
		
		String textOutput = new String(plainText.toByteArray());
		System.out.println("output text: " + textOutput);
		
	}
}
