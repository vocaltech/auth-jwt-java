package fr.vocaltech.auth.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;
import java.util.Base64;

public class JwtDemo {
    @SuppressWarnings("SpellCheckingInspection")
    private static final String SECRET_KEY_HS256 = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";

    @SuppressWarnings("SpellCheckingInspection")
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY0NDg0MjU2OCwiZXhwIjoxNjQ0ODQ2MTY4fQ.jAV7WWlLMcieOoa68qLyr2BuGJqL4aYpBGBzF-Q4tj8ywYIbItgwOgHOKJquOPYsA2dkAFtCOQJl1ESXHNCloA";

    /**
     * Generate a secret key HS256
     * @return the secret key
     */
    public static String generateSecretKeyHS256() {
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Issue JWT token
     * @param privateKey the private key to use to sign the payload
     * @return the Jwt token
     */
    public static String issueJwt(String privateKey) {
        // The JWT signature algorithm we will use to sign the payload
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // Generate the private key
        byte[] rawSecretKey = DatatypeConverter.parseBase64Binary(SECRET_KEY_HS256);
        Key signingKey = new SecretKeySpec(rawSecretKey, signatureAlgorithm.getJcaName());

        // generate a signed jwt token
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .setIssuedAt(new Date(1644842568000L)) // 2022-02-14T13:42:48+01:00
                .setExpiration(new Date(1644846168000L)) // 2022-02-14T14:42:48+01:00
                .signWith(signingKey);

        return jwtBuilder.compact();
    }

    public static void main(String[] args) {
        String jwtToken = issueJwt(SECRET_KEY_HS256);
        System.out.println(jwtToken);
    }
}
