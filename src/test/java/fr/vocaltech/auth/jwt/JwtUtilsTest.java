package fr.vocaltech.auth.jwt;

import com.google.gson.JsonObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import static com.google.common.truth.Truth.assertThat;

@TestMethodOrder(OrderAnnotation.class)
class JwtUtilsTest {
    /*
        Payload format
        ===========================
        {
            "sub": "1234567890",
            "name": "John Doe",
            "admin": true,
            "iat": 1645039380,
            "exp": 1645042980
        }
        ===========================
    */
    static SecretKey secret_key_hs256;
    static String jwtToken;
    static PrivateKey privateKey;
    static PublicKey publicKey;

    @Test
    @Order(1)
    void testIssueJwtWithExpiration() {
        // Create the payload
        JsonObject payload = new JsonObject();
        payload.addProperty("sub", "1234567890");
        payload.addProperty("name", "John Doe");
        payload.addProperty("admin", true);

        // Issue JWT token
        secret_key_hs256 = JwtUtils.generateSecretKeyHS256();
        long expiresAfter = 1 * 60 * 60 * 1000; // 1 hour
        jwtToken = JwtUtils.issueJwt(payload, expiresAfter, secret_key_hs256 , SignatureAlgorithm.HS256);

        System.out.println("token with expiration: " + jwtToken);
    }

    @Test
    @Order(2)
    void testDecodeJwtWithExpiration() {
        // Decode JWT token
        try {
            Claims claims = JwtUtils.decodeJwt(secret_key_hs256, SignatureAlgorithm.HS256, jwtToken);

            assertThat(claims.getSubject()).matches("1234567890");
            assertThat(claims.get("name", String.class)).matches("John Doe");
            assertThat(claims.get("admin", Boolean.class)).isTrue();

            long iat = claims.getIssuedAt().toInstant().toEpochMilli();
            long expiresAfter = 1 * 60 * 60 * 1000; // 1 hour

            assertThat(claims.getExpiration().toInstant().toEpochMilli()).isEqualTo(iat + expiresAfter);

        } catch (JwtException jwtException) {
            System.err.println(jwtException.getMessage());
        }
    }

    @Test
    @Order(3)
    void testIssueJwtNoExpiration() {
        // Create the payload
        JsonObject payload = new JsonObject();
        payload.addProperty("sub", "1234567890");
        payload.addProperty("name", "John Doe");
        payload.addProperty("admin", true);

        // Issue JWT token
        jwtToken = JwtUtils.issueJwt(payload, null, secret_key_hs256, SignatureAlgorithm.HS256);

        System.out.println("token with no expiration: " + jwtToken);
    }

    @Test
    @Order(4)
    void testDecodeJwtWithNoExpiration() {
        // Decode JWT token
        try {
            Claims claims = JwtUtils.decodeJwt(secret_key_hs256, SignatureAlgorithm.HS256, jwtToken);

            assertThat(claims.getSubject()).matches("1234567890");
            assertThat(claims.get("name", String.class)).matches("John Doe");
            assertThat(claims.get("admin", Boolean.class)).isTrue();
            assertThat(claims.getExpiration()).isNull();

        } catch (JwtException jwtException) {
            System.err.println(jwtException.getMessage());
        }
    }

    @Test
    @Order(5)
    void testGenerateKeyPairRSA() {
        KeyPair keyPair = JwtUtils.generateKeyPairRSA();

        assert keyPair != null;

        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();

        System.out.println("privateKey\n" + Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println();
        System.out.println("publicKey\n" + Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()));

        assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
        assertThat(privateKey).isInstanceOf(PrivateKey.class);

        assertThat(publicKey.getAlgorithm()).isEqualTo("RSA");
        assertThat(publicKey).isInstanceOf(PublicKey.class);
    }

    /*
    @Test
    @Order(6)
    void testIssueJwtWithPrivateKey() {
        // Create the payload
        JsonObject payload = new JsonObject();
        payload.addProperty("sub", "1234567890");
        payload.addProperty("name", "John Doe");
        payload.addProperty("admin", true);

        // Issue JWT token
        jwtToken = JwtUtils.issueJwt(payload, null, privateKey, signatureAlgorithm);

        System.out.println("token with no expiration: " + jwtToken);
    }

    @Test
    @Order(7)
    void testDecodeJwtWithPublicKey() {

    }

    @Test
    @Order(8)
    void testGenerateRSAPEM() {
        KeyPair keyPair = JwtUtils.generateKeyPairRSA();

        assert keyPair != null;

        String[] pemKeys = JwtUtils.generateRSAPEM(keyPair);

        assertThat(pemKeys[0]).startsWith("-----BEGIN PRIVATE KEY-----");
        assertThat(pemKeys[0]).endsWith("-----END PRIVATE KEY-----");

        assertThat(pemKeys[1]).startsWith("-----BEGIN PUBLIC KEY-----");
        assertThat(pemKeys[1]).endsWith("-----END PUBLIC KEY-----");
    }
    */
}