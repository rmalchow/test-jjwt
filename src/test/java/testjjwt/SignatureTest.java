package testjjwt;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import testjwt.DefaultKeyGenerator;
import testjwt.DefaultKeyProvider;
import testjwt.TokenReader;
import testjwt.TokenWriter;

public class SignatureTest {
	
	DefaultKeyGenerator dkg; 
	DefaultKeyProvider dpk; 
	
	TokenReader tr;
	TokenWriter tw;
	
	@Test
	public void testECsignature() {
		
		dkg = new DefaultKeyGenerator();
		dkg.setAlgorithm("EC");

		dpk = new DefaultKeyProvider();
		dpk.setKeyGenerator(dkg);
		
		tr = new TokenReader();
		tr.setKeyProvider(dpk);
		
		tw = new TokenWriter();
		tw.setKeyProvider(dpk);
		
		for(int i = 0; i< 1000; i++) {
			try {
				encodeDecode();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		
	}

	private void encodeDecode() throws Exception {
		dpk.generateKeyPair();
		
		Map<String,Object> claims1 = new HashMap<>();
		claims1.put("foo", "bar");
		claims1.put("x", System.currentTimeMillis());
		
		String s1 = tw.createToken(claims1, new Date(System.currentTimeMillis()+10000));
		
		Map<String,Object> claims2 = tr.readToken(s1);
		
		Assert.assertEquals("bar", claims2.get("foo"));
		Assert.assertEquals(claims1.get("x"), claims2.get("x"));
		
		
	}

}
