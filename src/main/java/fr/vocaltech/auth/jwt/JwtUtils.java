package fr.vocaltech.auth.jwt;

import com.google.gson.JsonObject;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class JwtUtils {
    /**
     * Generate a secret key HS256
     * @return the secret key
     */
    public static SecretKey generateSecretKeyHS256() {
        return Keys.secretKeyFor(SignatureAlgorithm.HS256);
    }

    public static String[] generateRSAPEM(KeyPair rsaKeyPair) {
        String[] pemKeys = new String[2];

        // generate private key
        PrivateKey privateKey = rsaKeyPair.getPrivate();
        pemKeys[0] = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()) +
                "\n-----END PRIVATE KEY-----";

        // generate public key
        PublicKey publicKey = rsaKeyPair.getPublic();
        pemKeys[1] = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()) +
                "\n-----END PUBLIC KEY-----";

        return pemKeys;
    }

    public static KeyPair generateKeyPairRSA() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
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
     * @param privateOrSecretKey the private/secret key to use to sign the payload
     * @param signatureAlgorithm the algorithm to be used for the signature
     * @return the Jwt token
     */
    public static String issueJwt(JsonObject payload, Long expiresAfter, Key privateOrSecretKey, SignatureAlgorithm signatureAlgorithm) {
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

        return jwtBuilder.signWith(privateOrSecretKey).compact();
    }

    /**
     *
     * @param publicOrSecretKey the public/secret key used to sign the payload
     * @param signatureAlgorithm the algorithm used for the  payload signature
     * @param jwtToken the JWS token
     * @return claims
     * @throws JwtException Exception ...
     */
    public static Claims decodeJwt(Key publicOrSecretKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(publicOrSecretKey)
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }
}
