package testjwt;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class DefaultKeyProvider {

	private DefaultKeyGenerator keyGenerator;
	private Map<Long,PublicKey> publicKeys = new HashMap<>();
	private PrivateKey privateKey;
	private String algorithm;
	private long serial;
	
	public void generateKeyPair() throws NoSuchAlgorithmException {
		try {

			KeyPair kp = getKeyGenerator().generateKeyPair();
			
			serial = System.currentTimeMillis();
			
			publicKeys.put(serial, kp.getPublic());
			this.privateKey = kp.getPrivate();

		} catch (NoSuchAlgorithmException e) {
			throw new NoSuchAlgorithmException();
		}
	}

	public PublicKey getPublicKey(long serial) throws NoSuchAlgorithmException {
		return publicKeys.get(serial);
	}

	public long getSerial() {
		return serial;
	}
	
	public PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
		return privateKey;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public DefaultKeyGenerator getKeyGenerator() {
		return keyGenerator;
	}

	public void setKeyGenerator(DefaultKeyGenerator keyGenerator) {
		this.keyGenerator = keyGenerator;
	}
	
	

}