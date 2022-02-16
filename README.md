# Jwt using Java
### Generate a JWT token

```
String issueJwt(JsonObject payload, long expiresAfter, String privateKey, SignatureAlgorithm signatureAlgorithm)
```

### Decode a JWT token

```
Claims decodeJwt(String publicKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException
```