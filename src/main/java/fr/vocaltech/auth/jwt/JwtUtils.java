package fr.vocaltech.auth.jwt;

import com.google.gson.JsonObject;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class JwtUtils {
    @SuppressWarnings("SpellCheckingInspection")
    private static final String SECRET_KEY_HS256 = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";

    @SuppressWarnings("SpellCheckingInspection")
    //private static final String JWT_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY0NDg0MjU2OCwiZXhwIjoxNjQ0ODQ2MTY4fQ.jAV7WWlLMcieOoa68qLyr2BuGJqL4aYpBGBzF-Q4tj8ywYIbItgwOgHOKJquOPYsA2dkAFtCOQJl1ESXHNCloA";
    private static final String JWT_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY0NDk1NDk3OCwiZXhwIjoxNjQ0OTU4NTc4fQ._YMGRlZkyhHQ3mSzVvNV5CUX-YYpouSjnskvbqvlsRoe8dTpSJCSKZifVeovqxKGUjuOU_fEWJ0s2kKrSH8x8A";

    /**
     * Generate a secret key HS256
     * @return the secret key
     */
    public static String generateSecretKeyHS256() {
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Generate a key from a string
     * @param key a key as a string
     * @param signatureAlgorithm the algorithm to be used
     * @return the key
     */
    public static Key generateKeyFromString(String key, SignatureAlgorithm signatureAlgorithm) {
        byte[] rawSecretKey = DatatypeConverter.parseBase64Binary(key);
        return new SecretKeySpec(rawSecretKey, signatureAlgorithm.getJcaName());
    }

    /**
     * Issue JWT token (JWS)
     * @param privateKey the private key to use to sign the payload
     * @param signatureAlgorithm the algorithm to be used for the signature
     * @return the Jwt token
     */
    public static String issueJwt(JsonObject payload, long expiresAfter, String privateKey, SignatureAlgorithm signatureAlgorithm) {
        Key signingKey = generateKeyFromString(privateKey, signatureAlgorithm);

        long iat = Instant.now().getEpochSecond() * 1000;
        long exp = iat + expiresAfter;

        /*
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .setIssuedAt(new Date(1644954978000L))
                .setExpiration(new Date(1644958578000L))
                .signWith(signingKey);

         */

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(payload.get("sub").toString())
                .claim("name", payload.get("name").toString())
                .claim("admin", payload.get("admin"))
                .setIssuedAt(new Date(iat))
                .setExpiration(new Date(exp))
                .signWith(signingKey);

        return jwtBuilder.compact();
    }

    public static Claims decodeJwt(String publicKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException {
        Key key = generateKeyFromString(publicKey, signatureAlgorithm);

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }
}
