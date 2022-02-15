package fr.vocaltech.auth.jwt;

import io.jsonwebtoken.*;
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
    public static String issueJwt(String privateKey, SignatureAlgorithm signatureAlgorithm) {
        Key signingKey = generateKeyFromString(privateKey, signatureAlgorithm);

        /*
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .setIssuedAt(new Date(1644842568000L)) // 2022-02-14T13:42:48+01:00
                .setExpiration(new Date(1644846168000L)) // 2022-02-14T14:42:48+01:00
                .signWith(signingKey);

         */

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .setIssuedAt(new Date(1644954978000L))
                .setExpiration(new Date(1644958578000L))
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

    public static void main(String[] args) {
        // The JWT signature algorithm we will use to sign the payload
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // Issue JWT token
        String jwtToken = issueJwt(SECRET_KEY_HS256, signatureAlgorithm);
        System.out.println(jwtToken);

        // Decode JWT token
        try {
            Claims claims = decodeJwt(SECRET_KEY_HS256, signatureAlgorithm, jwtToken);

            System.out.println("sub: " + claims.getSubject() );
            System.out.println("iat: " + claims.getIssuedAt());
            System.out.println("exp: " + claims.getExpiration());
            System.out.println("name: " + claims.get("name", String.class));
            System.out.println("admin: " + claims.get("admin", Boolean.class));

        } catch (JwtException jwtException) {
            System.err.println(jwtException.getMessage());
        }
    }
}
