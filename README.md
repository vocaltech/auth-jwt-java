# Jwt using Java
### Generate a JWT token

```

/**
 *
 * @param payload the payload in JSON format
 * @param expiresAfter exp claim value (set null for no expiration)
 * @param privateOrSecretKey the private/secret key to use to sign the payload
 * @param signatureAlgorithm the algorithm to be used for the signature
 * @return the Jwt token
 */
String issueJwt(JsonObject payload, long expiresAfter, Key privateOrSecretKey, SignatureAlgorithm signatureAlgorithm)

```

### Decode a JWT token

```
/**
 *
 * @param publicOrSecretKey the public/secret key used to sign the payload
 * @param signatureAlgorithm the algorithm used for the  payload signature
 * @param jwtToken the JWS token
 * @return claims
 * @throws JwtException Exception ...
 */
Claims decodeJwt(Key publicOrSecretKey, SignatureAlgorithm signatureAlgorithm, String jwtToken) throws JwtException
```