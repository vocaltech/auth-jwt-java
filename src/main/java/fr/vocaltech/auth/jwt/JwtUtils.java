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
     *
     * @param payload the payload in JSON format
     * @param expiresAfter expiresAfter value
     * @param privateKey the private key to use to sign the payload
     * @param signatureAlgorithm the algorithm to be used for the signature
     * @return the Jwt token
     */
    public static String issueJwt(JsonObject payload, Long expiresAfter, String privateKey, SignatureAlgorithm signatureAlgorithm) {
        Key signingKey = generateKeyFromString(privateKey, signatureAlgorithm);

        long iat = Instant.now().getEpochSecond() * 1000;
        long exp;

        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(payload.get("sub").getAsString())
                .claim("name", payload.get("name").getAsString())
                .claim("admin", payload.get("admin"))
                .setIssuedAt(new Date(iat));

        if (expiresAfter == null) {
            jwtBuilder.setExpiration(null);
        } else {
            exp = iat + expiresAfter;
            jwtBuilder.setExpiration(new Date(exp));
        }

        return jwtBuilder.signWith(signingKey).compact();
    }

    /**
     *
     * @param publicKey the public key (public/private keypair used to sign the payload)
     * @param signatureAlgorithm the algorithm used for the  payload signature
     * @param jwtToken the JWS token
     * @return claims
     * @throws JwtException Exception ...
     */
    public static Claims decodeJwt(String publicKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException {
        Key key = generateKeyFromString(publicKey, signatureAlgorithm);

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }
}
