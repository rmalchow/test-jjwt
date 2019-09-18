package testjwt;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenWriter {
	
	private DefaultKeyProvider keyProvider;
	
	public String createToken(Map<String,Object> map, Date expires) throws NoSuchAlgorithmException {
		PrivateKey pk = keyProvider.getPrivateKey();
		long serial = keyProvider.getSerial();
		JwtBuilder b = Jwts.builder();
		b = b.setHeaderParam("serial", serial+"");
		b = b.setExpiration(expires);
		b = b.addClaims(map);
		if(pk.getAlgorithm().equals("RSA")) {
			b = b.signWith(SignatureAlgorithm.RS256, pk);
		} else if(pk.getAlgorithm().equals("EC")) {
			b = b.signWith(SignatureAlgorithm.ES256, pk);
		} else {
			throw new NoSuchAlgorithmException();
		}
		return b.compact();
	}
	
	public DefaultKeyProvider getKeyProvider() {
		return keyProvider;
	}

	public void setKeyProvider(DefaultKeyProvider keyProvider) {
		this.keyProvider = keyProvider;
	}
	
	
}
