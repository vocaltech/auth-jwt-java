package fr.vocaltech.auth.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.*;

public class JwtDemo {
    public static String issueJwt() {
        // generate a secret key HS256
        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);
        String keyStr = Base64.getEncoder().encodeToString(key.getEncoded());
        System.out.println(keyStr);

        // generate a signed jwt token
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject("1234567890")
                .claim("name", "John Doe")
                .claim("admin", true)
                .setIssuedAt(new Date(1644840928000L)) // 2022-02-14T13:15:28+01:00
                .setExpiration(new Date(1644844528000L)) // 2022-02-14T14:15:28+01:00
                .signWith(key);

        return jwtBuilder.compact();
    }

    public static void main(String[] args) {
        String jwtToken = issueJwt();
        System.out.println(jwtToken);
    }
}
