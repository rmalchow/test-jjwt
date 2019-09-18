package testjwt;

import java.security.Key;
import java.util.Map;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolver;

public class TokenReader {

	private DefaultKeyProvider keyProvider;
	
	private Resolver resolver = new Resolver();
	
	public String getString(Map<String,Object> claims, String claimName, String def) {
		if(claims.get(claimName)==null) return def;
		return claims.get(claimName).toString();
	}
	
	public boolean getBoolean(Map<String,Object> claims, String claimName, boolean def) {
		if(claims.get(claimName)==null) return def;
		return ((Boolean)claims.get(claimName)).booleanValue();
	}
	
	public Map<String,Object> readToken(String in) throws Exception {
		if(in == null || in.trim().length()==0) return null;
		try {

			JwtParser p = Jwts.parser();
			p = p.setSigningKeyResolver(resolver);
			
			Map<String,Object> m = Jwts.parser().setSigningKeyResolver(resolver).parseClaimsJws(in).getBody();

			return m;
		} catch (ExpiredJwtException e1) {
			throw new Exception("token expired");
		} catch (Exception e2) {
			throw new Exception("token error (other)",e2);
		} 
	}

	public DefaultKeyProvider getKeyProvider() {
		return keyProvider;
	}

	public void setKeyProvider(DefaultKeyProvider keyProvider) {
		this.keyProvider = keyProvider;
	}
	

	private class Resolver implements SigningKeyResolver {
		
		public Key resolveSigningKey(@SuppressWarnings("rawtypes") JwsHeader header, Claims claims) {
			return (resolveSigningKey(header, ""));
		}

		public Key resolveSigningKey(@SuppressWarnings("rawtypes") JwsHeader header, String plaintext) {
			try {
				if(header.get("serial")==null) {
					throw new Exception("no serial");
				}
				Long s = Long.parseLong(header.get("serial")+"");
				Key k = keyProvider.getPublicKey(s);
				if(k==null) {
					throw new Exception("key not foung");
				}
				return k;
			} catch (Exception e) {
				throw new RuntimeException("could not find key to verify signature!");
			}
		}
		
	}
	
	
	
}