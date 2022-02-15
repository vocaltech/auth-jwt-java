package fr.vocaltech.auth.jwt;

import org.junit.jupiter.api.Test;
import static com.google.common.truth.Truth.assertThat;

import static org.junit.jupiter.api.Assertions.*;

class JwtDemoTest {

    @Test
    void issueJwt() {
        String JWT_TOKEN = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTY0NDk1NDk3OCwiZXhwIjoxNjQ0OTU4NTc4fQ._YMGRlZkyhHQ3mSzVvNV5CUX-YYpouSjnskvbqvlsRoe8dTpSJCSKZifVeovqxKGUjuOU_fEWJ0s2kKrSH8x8A";

        assertThat(JWT_TOKEN).startsWith("eyJh");
    }
}