# JWT
A simple PHP class to encode and decode JSON Web Tokens (JWT), conforming to RFC 7519.
Supported algorithms: HS256, HS512, HS384, RS256, RS384, RS512.

Installation
------------
```code
	composer require gozoro/jwt
```

Usage
-----


**Encode**
```php
$key     = 'my_secret_key';
$tokenId = '12345';
$beginTs = time();
$endTs   = $beginTs + 3600;
$issuer  = 'oauth.example.com';
$subject = 'subject',
$audience= 'audience',

try
{
	$jwt = new \gozoro\jwt\JWT('HS256');
	$jwt->setTokenId($tokenId);
	$jwt->setNotBeforeTime($beginTs);
	$jwt->setExpirationTime($endTs);
	$jwt->setIssuedAtTime($beginTs);
	$jwt->setIssuer($issuer);
	$jwt->setSubject($subject);
	$jwt->setAudience(audience);

	print $jwtstr = \gozoro\jwt\JWT::encode($jwt, $key);
}
catch(\gozoro\jwt\JwtEncodeException $e)
{
	print $e->getMessage();
}
```

or

```php
try
{
	$payload = [
		'jti' => $tokenId,
		'nbf' => $beginTs,
		'exp' => $endTs,
		'iat' => $beginTs,
		'iss' => $issuer,
		'sub' => $subject,
		'aud' => $audience,
	];

	$jwt = new \gozoro\jwt\JWT('HS256');
	$jwt->setPayload($payload);

	print $jwtstr = \gozoro\jwt\JWT::encode($jwt, $key);
}
catch(\gozoro\jwt\JwtEncodeException $e)
{
	print $e->getMessage();
}
```


**Decode**
```php
try
{
	$jwt = \gozoro\jwt\JWT::decode($jwtstr);

	print $jwt->getTokenId();
	print $jwt->getNotBeforeTimeFormatted('Y-m-d H:i:s');
	print $jwt->getExpirationTimeFormatted('Y-m-d H:i:s');
	print $jwt->getIssuedAtTimeFormatted('Y-m-d H:i:s');
	print $jwt->getIssuer();
	print $jwt->getAudience();

	print_r($jwt->getHeader());
	print_r($jwt->getPayload());
	print $jwt->getSignature();
}
catch(\gozoro\jwt\JwtDecodeException $e)
{
	print $e->getMessage();
}
```

**Validate**
```php

	$key    = 'my_secret_key';
	$leeway = 300;

	if($jwt->validateHeader())
		print 'Header: OK';

	if($jwt->validateSignature($key))
		print 'Signature: OK';

	if($jwt->validateNotBeforeTime($leeway))
		print 'Not Before Time: OK';

	if($jwt->validateExpirationTime($leeway))
		print 'Expiration Time: OK';

	if($jwt->validateTime($leeway)) // $jwt->validateNotBeforeTime($leeway) and $jwt->validateExpirationTime($leeway)
		print 'Time: OK';
```

