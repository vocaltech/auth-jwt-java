# Jwt using Java
### Generate a JWT token

```
String issueJwt(String privateKey, SignatureAlgorithm signatureAlgorithm)
```

### Decode a JWT token

```
Claims decodeJwt(String publicKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException
```