package fr.vocaltech.auth.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;
import static com.google.common.truth.Truth.assertThat;

class JwtDemoTest {

    @Test
    void issueJwt() {
        @SuppressWarnings("SpellCheckingInspection")
        String SECRET_KEY_HS256 = "NTNv7j0TuYARvmNMmWXo6fKvM4o6nv/aUi9ryX38ZH+L1bkrnD1ObOQ8JAUmHCBq7Iy7otZcyAagBLHVKvvYaIpmMuxmARQ97jUVG16Jkpkp1wXOPsrF9zwew6TpczyHkHgX5EuLg2MeBuiT/qJACs1J0apruOOJCg/gOtkjB4c=";
        String JWT_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY0NDk1NDk3OCwiZXhwIjoxNjQ0OTU4NTc4fQ._YMGRlZkyhHQ3mSzVvNV5CUX-YYpouSjnskvbqvlsRoe8dTpSJCSKZifVeovqxKGUjuOU_fEWJ0s2kKrSH8x8A";

        // The JWT signature algorithm we will use to sign the payload
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // Issue JWT token
        String jwtToken = JwtDemo.issueJwt(SECRET_KEY_HS256, signatureAlgorithm);
        assertThat(jwtToken).matches(JWT_TOKEN);
    }
}