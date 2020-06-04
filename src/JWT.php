<?php

namespace gozoro\jwt;


use InvalidArgumentException;


/**
 * JSON Web Token implementation by RFC7519<br />
 * https://tools.ietf.org/html/rfc7519<br />
 * https://jwt.io/<br />
 * https://github.com/gozoro/jwt<br />
 *
 * Supported algorithms: HS256, HS512, HS384, RS256, RS384, RS512.
 * 
 * @author gozoro <gozoro@yandex.ru>
 */
class JWT
{
	/**
	 * Encryption algorithm hash_hmac SHA256.
	 */
	const ALG_HS256 = 'HS256';

	/**
	 * Encryption algorithm hash_hmac SHA384.
	 */
	const ALG_HS384 = 'HS384';

	/**
	 * Encryption algorithm hash_hmac SHA512.
	 */
	const ALG_HS512 = 'HS512';

	/**
	 * Encryption algorithm openssl SHA256.
	 */
	const ALG_RS256 = 'RS256';

	/**
	 * Encryption algorithm openssl SHA384.
	 */
	const ALG_RS384 = 'RS384';

	/**
	 * Encryption algorithm openssl SHA512.
	 */
	const ALG_RS512 = 'RS512';

	/**
	 * Supported encryption algorithms.
	 * @var array
	 */
	static protected $algorithms = array(
        self::ALG_HS256 => array('hash_hmac', 'SHA256'),
		self::ALG_HS384 => array('hash_hmac', 'SHA384'),
        self::ALG_HS512 => array('hash_hmac', 'SHA512'),
        self::ALG_RS256 => array('openssl', 'SHA256'),
        self::ALG_RS384 => array('openssl', 'SHA384'),
        self::ALG_RS512 => array('openssl', 'SHA512'),
    );

	/**
	 * Header
	 * @var array
	 */
	protected $header;

	/**
	 * Payload
	 * @var array
	 */
	protected $payload;

	/**
	 * Signature
	 * @var string
	 */
	protected $signature;

	/**
	 * Stores an encrypted message.
	 * @var string
	 */
	protected $signmsg;





	/**
	 * JSON Web Token implementation by RFC7519
	 * @param string $algorithm Algorithms: HS256, HS384, HS512, RS256, RS384, RS512. Default: HS256.
	 * @throws InvalidArgumentException
	 */
	public function __construct($algorithm = 'HS256')
	{
		if(isset(static::$algorithms[$algorithm]))
		{
			$this->header = array(
					'typ' => 'JWT',
					'alg' => $algorithm
				);

			$this->payload   = array();
			$this->signature = null;
			$this->signmsg   = null;
		}
		else
		{
			throw new InvalidArgumentException("Unknow algorithm [$algorithm].");
		}
	}

	/**
	 * Returns the encryption algorithm of the signature.
	 *
	 * @return string
	 */
	public function getAlgorithm()
	{
		if(isset($this->header['alg']))
		{
			return (string)$this->header['alg'];
		}
		else
		{
			return null;
		}
	}

	/**
	 * Sets header array
	 * @param array $header
	 */
	public function setHeader(array $header)
	{
		$this->signmsg   = null;
		$this->signature = null;

		$this->header = (array)$header;
	}

	/**
	 * Returns header array
	 * @return array
	 */
	public function getHeader()
	{
		return $this->header;
	}

	/**
	 * Sets payload
	 * @param array $payload
	 */
	public function setPayload(array $payload)
	{
		$this->signmsg   = null;
		$this->signature = null;

		$this->payload = (array)$payload;
	}

	/**
	 * Returns payload array
	 * @return array
	 */
	public function getPayload()
	{
		return $this->payload;
	}

	/**
	 * Returns signature or NULL if JWT is not signed.
	 * @return string|NULL
	 */
	public function getSignature()
	{
		return $this->signature;
	}

	/**
	 * Sets claim value
	 * @param string $name claim name
	 * @param mixed $value
	 * @return static
	 */
	public function setClaim($name, $value)
	{
		$this->payload[$name] = $value;

		// After setter signature is not valid.
		$this->signmsg   = null;
		$this->signature = null;

		return $this;
	}

	/**
	 * Returns value of claim
	 * @param string $name Claim name
	 * @return mixed
	 */
	public function getClaim($name)
	{
		if(isset($this->payload[$name]))
			return $this->payload[$name];
		else
			return null;
	}

	/**
	 *
	 * @param string $name
	 * @param int|string $value timestamp or date string
	 * @param string $exceptionString message for exception
	 * @return static
	 * @throws InvalidArgumentException
	 */
	protected function setTimeClaim($name, $value, $exceptionString)
	{
		if(is_int($value))
		{
			$ts = (int)$value;
			if($ts <=0)
				throw new InvalidArgumentException($exceptionString);
		}
		elseif(is_string($value))
		{
			$ts = strtotime($value);
			if($ts === false)
				throw new InvalidArgumentException($exceptionString);
		}
		else
		{
			throw new InvalidArgumentException($exceptionString);
		}

		return $this->setClaim($name, $ts);
	}

	/**
	 * Returns time value.
	 *
	 * @param string $name Claim name
	 * @return int|NULL
	 */
	protected function getTimeClaim($name)
	{
		if(isset($this->payload[$name]))
		{
			return (int)$this->payload[$name];
		}
		else
			return null;
	}

	/**
	 * Returns formatted time value.
	 *
	 * @param string $name Claim name
	 * @param string $format The format of the outputted date string (look function date())
	 * @return string|NULL
	 */
	protected function getTimeClaimFormatted($name, $format = 'Y-m-d H:i:s')
	{
		if($ts = $this->getTimeClaim($name))
		{
			return date($format, $ts);
		}
		else
			return null;
	}

	/**
	 * Sets expiration time ( payload[exp]).
	 * The "exp" claim identifies the expiration time on
	 * or after which the JWT MUST NOT be accepted for processing.
	 *
	 * @param int|string $value timestamp or formatted date string
	 * @return static
	 */
	public function setExpirationTime($value)
	{
		return $this->setTimeClaim('exp', $value, 'Invalid expiration time.');
	}

	/**
	 * Returns expiration time ( payload[exp] ) as timestamp.
	 *
	 * @return int|NULL
	 */
	public function getExpirationTime()
	{
		return $this->getTimeClaim('exp');
	}

	/**
	 * Returns formatted expiration time ( payload[exp] ) as formatted date string.
	 *
	 * @param string $format The format of the outputted date string (look function date())
	 * @return string|NULL
	 */
	public function getExpirationTimeFormatted($format = 'Y-m-d H:i:s')
	{
		return $this->getTimeClaimFormatted('exp', $format);
	}

	/**
	 * Sets Not Before time ( payload[nbf] ).
	 * The "nbf" (not before) claim identifies the time before
	 * which the JWT MUST NOT be accepted for processing.
	 *
	 * @param int|string $value timestamp or formatted date string
	 * @return int|NULL
	 */
	public function setNotBeforeTime($value)
	{
		return $this->setTimeClaim('nbf', $value, 'Invalid Not Before time.');
	}

	/**
	 * Returns Not Before time ( payload[nbf] ) as timestamp.
	 *
	 * @return int|NULL
	 */
	public function getNotBeforeTime()
	{
		return $this->getTimeClaim('nbf');
	}

	/**
	 * Returns Not Before time ( payload[nbf] ) as formatted date string.
	 *
	 * @param string $format The format of the outputted date string (look function date())
	 * @return string|NULL
	 */
	public function getNotBeforeTimeFormatted($format = 'Y-m-d H:i:s')
	{
		return $this->getTimeClaimFormatted('nbf', $format);
	}

	/**
	 * Returns token duration.
	 *
	 * @return int|NULL
	 */
	public function getDuration()
	{
		if(isset($this->payload['nbf']) and isset($this->payload['exp']))
		{
			$exp = (int)$this->payload['exp'];
			$nbf = (int)$this->payload['nbf'];

			$duration = $exp - $nbf;

			if($duration >= 0)
				return $duration;
			else
				return null;
		}
		else
		{
			return null;
		}
	}

	/**
	 * Sets Issued At time ( payload[iat] ).
	 * The "iat" (issued at) claim identifies the time at which the JWT was issued.
	 *
	 * @param int|string $value timestamp or formatted date string
	 * @return int|NULL
	 */
	public function setIssuedAtTime($value)
	{
		return $this->setTimeClaim('iat', $value, 'Invalid Issued At time.');
	}

	/**
	 * Returns Issued At time ( payload[iat] ) as timestamp.
	 *
	 * @return int|NULL
	 */
	public function getIssuedAtTime()
	{
		return $this->getTimeClaim('iat');
	}

	/**
	 * Returns Issued At time ( payload[nbf] ) as formatted date string.
	 *
	 * @param string $format The format of the outputted date string (look function date())
	 * @return string|NULL
	 */
	public function getIssuedAtTimeFormatted($format = 'Y-m-d H:i:s')
	{
		return $this->getTimeClaimFormatted('iat', $format);
	}

	/**
	 * Sets token ID ( payload[jti] ).
	 *
	 * @param string $tokenId Case sensitive unique identifier of the token even among different issuers.
	 * @return static
	 * @throws InvalidArgumentException
	 */
	public function setTokenId($tokenId)
	{
		if($tokenId)
			return $this->setClaim('jti', (string)$tokenId);
		else
			throw new InvalidArgumentException("Invalid token ID.");
	}

	/**
	 * Returns unique token ID (payload[jti]).
	 * Returns NULL if payload[jti] is undefined.
	 *
	 * @return string|null
	 */
	public function getTokenId()
	{
		return $this->getClaim('jti');
	}

	/**
	 * Sets the subject of JWT (paylod[sub]).
	 *
	 * @param string $subject
	 * @return static
	 */
	public function setSubject($subject)
	{
		return $this->setClaim('sub', (string)$subject);
	}

	/**
	 * Returns the subject of JWT (paylod[sub]).
	 * Returns NULL if paylod[sub] is undefined.
	 *
	 * @return string|null
	 */
	public function getSubject()
	{
		return $this->getClaim('sub');
	}

	/**
	 * Sets issuer (payload[iss]). Sets name of the token generating service.
	 *
	 * @param string $issuer
	 * @return static
	 */
	public function setIssuer($issuer)
	{
		return $this->setClaim('iss', (string)$issuer);
	}

	/**
	 * Returns issuer (payload[iss]). Name of the token generating service.
	 * Returns NULL if payload[iss] is undefined.
	 *
	 * @return string|null
	 */
	public function getIssuer()
	{
		return $this->getClaim('iss');
	}

	/**
	 * Sets identifies the recipients that the JWT is intended for.
	 *
	 * @param array|string $aud string or URL
	 * @return static
	 */
	public function setAudience($aud)
	{
		return $this->setClaim('aud', $aud);
	}

	/**
	 * Returns array of the recipients that the JWT is intended for (payload[aud]).
	 * Each principal intended to process the JWT must identify itself with
	 * a value in the audience claim (payload[aud]). If the principal processing
	 * the claim does not identify itself with a value in the aud claim when this
	 * claim is present, then the JWT must be rejected.
	 *
	 * @return array|null
	 */
	public function getAudience()
	{
		return $this->getClaim('aud');
	}

	/**
	 * Validates the header of JWT.
	 * Returns TRUE if the header is correct. Otherwise returns FALSE.
	 *
	 * @reutrn boolean
	 */
	public function validateHeader()
	{
		if(!$this->header)
		{
			return false;
		}

		if(!isset($this->header['typ']))
		{
			return false;
		}

		if($this->header['typ'] != 'JWT')
		{
			return false;
		}


		if($alg = $this->getAlgorithm())
		{
			if(!isset(static::$algorithms[$alg]))
			{
				return false;
			}
		}
		else
		{
			return false;
		}

		return true;
	}

	/**
	 * Validates the signature in JWT token.
	 * Returns TRUE if the signature is correct. Otherwise returns FALSE.
	 *
	 * @param string $key Secret key or public key content for openssl.
	 * @return bool
	 * @throws JwtValidateException
	 */
	public function validateSignature($key)
	{
		if($this->validateHeader())
		{
			if(is_null($this->signature))
			{
				throw new JwtValidateException('Token is not signed.');
			}

			$alg = $this->getAlgorithm();
			list($function, $algorithm) = static::$algorithms[$alg];


			$msg = $this->signmsg;
			$signature = $this->signature;

			if($function == 'hash_hmac')
			{
				$hash = hash_hmac($algorithm, $msg, $key, true);

				if(function_exists('hash_equals'))
					return hash_equals($signature, $hash);
				else
					return ($signature === $hash);
			}
			elseif($function == 'openssl')
			{
				$public_key = openssl_get_publickey($key);

				if($public_key === false)
				{
					throw new JwtValidateException('OpenSSL error: ' . openssl_error_string() );
				}

				$success = openssl_verify($msg, $signature, $public_key, $algorithm);
				openssl_free_key($public_key);
				if($success === 1)
				{
					return true;
				}
				elseif($success === 0)
				{
					return false;
				}
				throw new JwtValidateException('OpenSSL error: ' . openssl_error_string() );
			}
			else
			{
				throw new JwtValidateException("Invalid algorithm function [$function].");
			}
		}
		else
			return false;
	}

	/**
	 * Validates "Not Before" time.
	 *
	 * @param int $leeway Some small leeway, usually no more than a few minutes, to account for clock skew (the measurement in seconds).
	 * @return boolean
	 */
	public function validateNotBeforeTime($leeway = 0)
	{
		$leeway = (int)$leeway;
		if($leeway < 0)
		{
			$leeway = 0;
		}

		$now = time();
		$nbf = $this->getNotBeforeTime();

		if(is_null($nbf)) return true;

		return ( $now >= ($nbf - $leeway) );
	}

	/**
	 * Validates expiration time.
	 *
	 * @param int $leeway Some small leeway, usually no more than a few minutes, to account for clock skew (the measurement in seconds).
	 * @return boolean
	 */
	public function validateExpirationTime($leeway = 0)
	{
		$leeway = (int)$leeway;
		if($leeway < 0)
		{
			$leeway = 0;
		}

		$now = time();
		$exp = $this->getExpirationTime();

		if(is_null($exp)) return true;

		return ( $now <= ($exp + $leeway) );
	}

	/**
	 * Validates "Not Before" time and expiration time of token.
	 *
	 * @param int $leeway Some small leeway, usually no more than a few minutes, to account for clock skew (the measurement in seconds).
	 * @return boolean
	 */
	public function validateTime($leeway = 0)
	{
		return $this->validateNotBeforeTime($leeway) and $this->validateExpirationTime($leeway);
	}

    /**
     * Encodes an array into a JSON string.
     * @param array $input input array
     * @return string JSON string
	 * @throws JwtEncodeException
     */
	static protected function jsonEncode($input)
	{
		$input = (array)$input;
		$json = json_encode($input);

		if($json === false)
		{
			throw new JwtEncodeException('Array cannot be encoded into JSON (json_last_error_msg='.json_last_error_msg().').');
		}
		else
		{
			return $json;
		}
	}

    /**
     * Decodes a JSON string into an associative array.
	 *
     * @param string $json JSON string
     * @return array
     * @throws JwtDecodeException
     */
    static protected function jsonDecode($json)
    {
		$arr = json_decode($json, true);

		if ($arr === null)
		{
            throw new JwtDecodeException('JSON cannot be decoded (json_last_error_msg='.json_last_error_msg().').');
        }
		else
		{
			return $arr;
		}
    }

	/**
	 * Encodes a string into base64 by RFC3548.<br />
	 * Symbol "+" replace to "-". Symbol "/" replace to "_".
     * And remove all symbols "=".
	 *
     * @param string $input
     * @return string
	 * @throws JwtEncodeException
     */
    static protected function base64urlEncode($input)
    {
        $base64 = base64_encode($input);
		if($base64 === false)
		{
			throw new JwtEncodeException('Encoding to Base64 failed.');
		}
		else
		{
			return str_replace('=', '', strtr($base64, '+/', '-_'));
		}
    }

    /**
     * Decodes a base64 string from encoded string with base64urlEncode().
	 *
     * @param string $input an encoded string
     * @return string A decoded string
	 * @throws JwtDecodeException
     */
    static protected function base64urlDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder)
		{
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }

		$decodedString = base64_decode(strtr($input, '-_', '+/'));

		if($decodedString === false)
		{
			throw new JwtDecodeException('Decoding to Base64 failed.');
		}
		else
		{
			return $decodedString;
		}
    }

    /**
	 * Signs the string with an encryption algorithm.
	 *
     * @param string $msg The message to sign
     * @param string $key The secret key or private key content for openssl
     * @param string $alg The signing algorithm. See constantss ALG_.
     * @return string Signature. For openssl signature is binary data!
     * @throws JwtEncodeException
     */
    static protected function sign($msg, $key, $alg)
    {
        if(is_null($alg))
		{
			throw new JwtEncodeException('Algorithm is undefined.');
		}

		if(!isset(static::$algorithms[$alg]))
		{
            throw new JwtEncodeException("Algorithm [$alg] not supported.");
        }

		$key = (string)$key;

        list($function, $algorithm) = static::$algorithms[$alg];

		if($function == 'hash_hmac')
		{
			return hash_hmac($algorithm, $msg, $key, true);
		}
		elseif($function == 'openssl')
		{
			$private_key = openssl_get_privatekey($key);

			if(!$private_key)
			{
				throw new JwtEncodeException('OpenSSL error: ' . openssl_error_string() );
			}

			$signature = '';
			$success = openssl_sign($msg, $signature, $private_key, $algorithm);
			openssl_free_key($private_key);

			if($success)
			{
				return $signature;
			}
			else
			{
				throw new JwtEncodeException("OpenSSL unable to sign data.");
			}
		}
    }

	/**
	 * Returns encoded JWT string.
	 *
	 * @param JWT $jwt
	 * @param string $key
	 * @return string
	 * @throws JwtEncodeException
	 */
	static function encode(JWT $jwt, $key)
	{
		$header_base64  = static::base64urlEncode(static::jsonEncode($jwt->header));
		$payload_base64 = static::base64urlEncode(static::jsonEncode($jwt->payload));

		$msg  = $header_base64.".".$payload_base64;
		$alg  = $jwt->getAlgorithm();
		$sign = static::sign($msg, $key, $alg);

		$signature_base64 = static::base64urlEncode($sign);

		return $msg.".".$signature_base64;
	}

	/**
	 * Returns decoded object JWT.
	 *
	 * @param string $jwtstr encoded string
	 * @return JWT
	 * @throws JwtDecodeException
	 */
	static function decode($jwtstr)
	{
		$jwtstr   = trim($jwtstr);
		$segments = explode('.', $jwtstr);

		if(count($segments) != 3)
		{
			throw new JwtDecodeException("Wrong number of JWT segments.");
		}

		list($header_base64, $payload_base64, $signature_base64) = $segments;

		$jwt = new static();
		$jwt->signmsg   = $header_base64.".".$payload_base64;
		$jwt->header    = static::jsonDecode( static::base64urlDecode($header_base64) );
		$jwt->payload   = static::jsonDecode( static::base64urlDecode($payload_base64) );
		$jwt->signature = static::base64urlDecode($signature_base64);

		return $jwt;
	}
}




class JwtEncodeException extends \Exception{}
class JwtDecodeException extends \Exception{}
class JwtValidateException extends JwtDecodeException{}