package testjwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

public class DefaultKeyGenerator  {

	private String algorithm = "EC";
	
	public DefaultKeyGenerator() {
	}

	public DefaultKeyGenerator(String algorithm) {
		this.algorithm = algorithm;
	}
	
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		if(algorithm.equals("RSA")) return generateRsaKeyPair();
		if(algorithm.equals("EC")) return generateEcKeyPair();
		throw new NoSuchAlgorithmException();
	}
	
	public KeyPair generateRsaKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(4096);
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}
	
	public KeyPair generateEcKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		    kpg.initialize(new ECGenParameterSpec("secp384r1"));
			return kpg.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException(e); 
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		if(algorithm==null) throw new NullPointerException();
		this.algorithm = algorithm;
	}
	
}