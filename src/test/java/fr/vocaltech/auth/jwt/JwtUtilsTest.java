package fr.vocaltech.auth.jwt;

import com.google.gson.JsonObject;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureAlgorithm;

import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

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

    @SuppressWarnings("SpellCheckingInspection")
    static String SECRET_KEY_HS256 = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";
    static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256; // The JWT signature algorithm we will use to sign the payload
    static String jwtToken;

    @Test
    @Order(1)
    void issueJwt() {
        // Create the payload
        JsonObject payload = new JsonObject();
        payload.addProperty("sub", "1234567890");
        payload.addProperty("name", "John Doe");
        payload.addProperty("admin", true);

        System.out.println("payload size: " + payload.size() + " - str: " + payload);

        // Issue JWT token
        long expiresAfter = 1 * 60 * 60 * 1000; // 1 hour
        jwtToken = JwtUtils.issueJwt(payload, expiresAfter, SECRET_KEY_HS256, signatureAlgorithm);

        System.out.println("issueJwt()" + jwtToken);
    }

    @Test
    @Order(2)
    void decodeJwt() {
        // Decode JWT token
        try {
            Claims claims = JwtUtils.decodeJwt(SECRET_KEY_HS256, signatureAlgorithm, jwtToken);

            assertThat(claims.getSubject()).matches("\"1234567890\"");
            assertThat(claims.get("name", String.class)).matches("\"John Doe\"");
            assertThat(claims.get("admin", Boolean.class)).isTrue();

            long iat = claims.getIssuedAt().toInstant().toEpochMilli();
            long expiresAfter = 1 * 60 * 60 * 1000; // 1 hour

            assertThat(claims.getExpiration().toInstant().toEpochMilli()).isEqualTo(iat + expiresAfter);

        } catch (JwtException jwtException) {
            System.err.println(jwtException.getMessage());
        }
    }
}