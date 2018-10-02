<?php

namespace gozoro\jwt;



/**
 * JSON Web Token implementation by RFC7519<br />
 * https://tools.ietf.org/html/rfc7519<br />
 * https://jwt.io/<br />
 *
 * Supported algorithms: HS256, HS512, HS384, RS256, RS384, RS512
 * @author gozoro <gozoro@yandex.ru>
 */
class JsonWebToken
{
	/**
	 * Encryption algorithms hash_hmac SHA256.
	 */
	const ALG_HS256 = 'HS256';

	/**
	 * Encryption algorithms hash_hmac SHA384.
	 */
	const ALG_HS384 = 'HS384';

	/**
	 * Encryption algorithms hash_hmac SHA512.
	 */
	const ALG_HS512 = 'HS512';

	/**
	 * Encryption algorithms openssl SHA256.
	 */
	const ALG_RS256 = 'RS256';

	/**
	 * Encryption algorithms openssl SHA384.
	 */
	const ALG_RS384 = 'RS384';

	/**
	 * Encryption algorithms openssl SHA512.
	 */
	const ALG_RS512 = 'RS512';


	/**
	 * Default algorithm.
	 */
	const DEFAULT_ALG = 'HS256';



	/**
	 * Supported encryption algorithms.
	 * @var array
	 */
	protected $supported_algs = array(
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
	 * Constructs an object of JWT token.
	 * @param string $jwt JWT token
	 */
	public function __construct($jwt = null)
	{
		if(is_null($jwt))
		{
			$this->header = array(
				'typ' => 'JWT',
				'alg' => static::DEFAULT_ALG
			);

			$this->payload = array();
			$this->signature = null;
		}
		else
		{
			list($header_base64, $payload_base64, $signature_base64) = $this->explode($jwt);

			$this->header    = $this->decodeHeader($header_base64);
			$this->payload   = $this->decodePayload($payload_base64);
			$this->signature = $this->decodeSignature($signature_base64);
		}
	}

	/**
	 * Sets the encryption algorithm of the signature
	 * from the list of supported algorithms.
	 * @param string $alg
	 * @return static
	 * @throws JsonWebTokenException
	 */
	public function setAlgorithm($alg)
	{
		if(isset($this->supported_algs[ $alg ]))
		{
			$this->header['alg'] = $alg;
		}
		else
		{
			throw new JsonWebTokenException("Undefined algorithm [$alg].");
		}

		return $this;
	}

	/**
	 * Returns the encryption algorithm of the signature.
	 * @return string
	 * @throws JsonWebTokenException
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
	 * Sets date and time on which the JWT will start to be accepted for processing (payload[nbf]).
	 * @param string $date
	 * @return static
	 */
	public function setDateBegin($date)
	{
		$ts = strtotime($date);
		if($ts === false)
		{
			throw new JsonWebTokenException("Invalid date [$date]");
		}
		else
		{
			$this->payload['nbf'] = $ts;
			unset($this->payload['exp']);
			return $this;
		}
	}


	/**
	 * Returns date and time on which the JWT will start to be accepted for processing (payload[nbf]).
	 * @param string $format The format of the outputted date string (look function date())
	 * @return string
	 * @throws JsonWebTokenException
	 */
	public function getDateBegin($format = 'Y-m-d H:i:s')
	{
		if(isset($this->payload['nbf']))
		{
			$nbf = (int)$this->payload['nbf'];
			return date($format, $nbf);
		}
		else
		{
			return null;
		}
	}

	/**
	 * Sets date and time on which the JWT will finish to be accepted for processing (payload[exp]).
	 * @param string $date
	 * @return static
	 * @throws JsonWebTokenException
	 */
	public function setDateEnd($date)
	{
		$ts = strtotime($date);
		if($ts === false)
		{
			throw new JsonWebTokenException("Invalid date [$date]");
		}
		else
		{
			$this->payload['exp'] = $ts;
			return $this;
		}
	}

	/**
	 * Returns date and time on which the JWT will finish to be accepted for processing (payload[exp]).
	 * Returns NULL if date end is undefined.
	 * @param string $format The format of the outputted date string (look function date()).
	 * @return string|null
	 */
	public function getDateEnd($format = 'Y-m-d H:i:s')
	{
		if(isset($this->payload['exp']))
		{
			$exp = (int)$this->payload['exp'];
			return date($format, $exp);
		}
		else
		{
			return null;
		}
	}

	/**
	 * Sets token duration.
	 * Sets payload[nbf] and payload[exp] automatically.
	 * @param int $duration
	 * @return static
	 * @throws JsonWebTokenException
	 */
	public function setDuration($duration)
	{
		$duration = (int)$duration;
		if($duration > 0)
		{
			if(isset($this->payload['nbf']) and $this->payload['nbf'] > 0)
			{
				$this->payload['exp'] = $this->payload['nbf'] + $duration;
			}
			else
			{
				$this->payload['nbf'] = time();
				$this->payload['exp'] = $this->payload['nbf'] + $duration;
			}
		}
		else
		{
			throw new JsonWebTokenException("Invalid value of token duration [$duration] sec.");
		}

		return $this;
	}

	/**
	 * Returns token duration.
	 * @return int
	 */
	public function getDuration()
	{
		if(isset($this->payload['nbf']) and isset($this->payload['exp']))
		{
			$exp = (int)$this->payload['exp'];
			$nbf = (int)$this->payload['nbf'];

			$duration = $exp - $nbf;

			if($duration > 0)
				return $duration;
			else
				throw new JsonWebTokenException("Invalid duration value [$duration].");
		}
		else
		{
			return null;
		}
	}

	/**
	 * Returns the time at which the JWT was issued.
	 * @return string
	 */
	public function getIssuedAt($format = 'Y-m-d H:i:s')
	{
		if(isset($this->payload['iat']))
		{
			$iat = (int)$this->payload['iat'];
			return date($format, $iat);
		}
		else
		{
			return null;
		}
	}


	/**
	 * Sets the subject of JWT (paylod[sub]).
	 * @param string $subject
	 * @return static
	 */
	public function setSubject($subject)
	{
		$this->payload['sub'] = (string)$subject;
		return $this;
	}

	/**
	 * Returns the subject of JWT (paylod[sub]).
	 * Returns NULL if paylod[sub] is undefined.
	 * @return string|null
	 */
	public function getSubject()
	{
		if(isset($this->payload['sub']))
		{
			return (string)$this->payload['sub'];
		}
		else
		{
			return null;
		}
	}

	/**
	 * Sets issuer (payload[iss]). sets name of the token generating service.
	 * @param string $issuer
	 * @return static
	 */
	public function setIssuer($issuer)
	{
		$this->payload['iss'] = (string)$issuer;
		return $this;
	}

	/**
	 * Returns issuer (payload[iss]). Name of the token generating service.
	 * Returns NULL if payload[iss] is undefined.
	 * @return string|null
	 */
	public function getIssuer()
	{
		if(isset($this->payload['iss']))
		{
			return (string)$this->payload['iss'];
		}
		else
		{
			return null;
		}
	}

	/**
	 * Identifies the recipients that the JWT is intended for.
	 * @param array|string $aud string or URL
	 * @return static
	 */
	public function setAudience($aud)
	{
		$this->payload['aud'] = (array)$aud;
		return $this;
	}

	/**
	 * Returns array of the recipients that the JWT is intended for (payload[aud]).
	 * Each principal intended to process the JWT must identify itself with
	 * a value in the audience claim (payload[aud]). If the principal processing
	 * the claim does not identify itself with a value in the aud claim when this
	 * claim is present, then the JWT must be rejected.
	 * @return array
	 */
	public function getAudience()
	{
		if(isset($this->payload['aud']))
		{
			return (array)$this->payload['aud'];
		}
		else
		{
			return [];
		}
	}

	/**
	 * Sets token ID ( payload[jti] )
	 * @param string $token Case sensitive unique identifier of the token even among different issuers.
	 * @return static
	 */
	public function setTokenId($token)
	{
		$this->payload['jti'] = (string)$token;
		return $this;
	}

	/**
	 * Returns unique token ID (payload[jti]).
	 * Returns NULL If payload[jti] is undefined.
	 * @return string|null
	 */
	public function getTokenId()
	{
		if(isset($this->payload['jti']))
			return $this->payload['jti'];
		else
			return null;
	}



	/**
	 * Encodes a string into base64 by RFC3548.<br />
	 * Symbol "+" replace to "-". Symbol "/" replace to "_".
     * And remove all symbols "=".
	 *
     * @param string $input
     * @return string
     */
    private function base64Encode($input)
    {
        $base64 = base64_encode($input);
		if($base64 === false)
		{
			throw new JsonWebTokenException('Encoding to Base64 failed.');
		}
		else
		{
			return str_replace('=', '', strtr($base64, '+/', '-_'));
		}
    }

    /**
     * Decodes a base64 string from encoded string with base64Encode().
	 *
     * @param string $input an encoded string
     * @return string A decoded string
     */
    private function base64Decode($input)
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
			throw new JsonWebTokenException('Dencoding to Base64 failed.');
		}
		else
		{
			return $decodedString;
		}
    }


    /**
     * Encodes an array into a JSON string
     *
     * @param array $arr input array
     * @return string JSON string
	 * @throws JsonWebTokenException
     */
    protected function jsonEncode($arr)
    {
        $arr = (array)$arr;
		$json = json_encode($arr);

		if($json === false)
		{
			throw new JsonWebTokenException('Array cannot be encoded into JSON (json_last_error='.json_last_error().').');
		}
		else
		{
			return $json;
		}
    }


    /**
     * Decodes a JSON string into an associative array
     *
     * @param string $json JSON string
     * @return array
     * @throws JsonWebTokenException
     */
    protected function jsonDecode($json)
    {
		$arr = json_decode($json, true);

		if ($arr === null)
		{
            throw new JsonWebTokenException('JSON cannot be decoded (json_last_error='.json_last_error().').');
        }
		else
		{
			return $arr;
		}
    }

	/**
	 * Splits the token into segments
	 * @param string $jwt JWT token
	 * @return array
	 */
	protected function explode($jwt)
	{
		$segments = explode('.', $jwt);

        if(count($segments) == 3)
		{
			return $segments;
		}
		else
		{
			throw new JsonWebTokenException('Wrong number of JWT segments.');
		}
	}


	/**
	 * Decodes and returns the header segment.
	 * @param string $header_base64 header segment into base64 enctyption
	 * @return array
	 * @throws JsonWebTokenException
	 */
	protected function decodeHeader($header_base64)
	{
		return (array)$this->jsonDecode( $this->base64Decode( $header_base64 ) );
	}


	/**
	 * Decodes and returns the payload segment.
	 * @param string $payload_base64 payload segment into base64 enctyption
	 * @return array
	 * @throws JsonWebTokenException
	 */
	protected function decodePayload($payload_base64)
	{
		return (array)$this->jsonDecode( $this->base64Decode( $payload_base64 ) );
	}

	/**
	 * Decodes and returns the signature segment.
	 * @param string $signature_base64 signature segment into base64 enctyption
	 * @return string
	 * @throws JsonWebTokenException
	 */
	protected function decodeSignature($signature_base64)
	{
		return $this->base64Decode($signature_base64);
	}


	/**
	 * Verifies the header of JWT.
	 * Returns TRUE if the header is correct. Otherwise returns FALSE.
	 * @reutrn boolean
	 */
	public function verifyHeader()
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

		if(isset($this->header['alg']))
		{
			$alg = (string)$this->header['alg'];

			if(!isset($this->supported_algs[$alg]))
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
     * Verifies the signature in JWT token.
	 * Returns TRUE if the signature is correct. Otherwise returns FALSE.
     *
     * @param string $key Secret key or public key content for openssl.
     *
     * @return bool
     * @throws JsonWebTokenException
     */
	public function verifySignature($key)
	{
		$signature = $this->signature;
		$alg       = $this->getAlgorithm();

		if(is_null($alg))
		{
			throw new Exception('Signature encryption algorithm is undefined.');
		}

        if(!isset($this->supported_algs[$alg]))
		{
            throw new Exception('Signature encryption algorithm not supported.');
        }

		list($function, $algorithm) = $this->supported_algs[$alg];

		$msg = $this->encryptedMessage();


		if($function == 'hash_hmac')
		{
			$hash = hash_hmac($algorithm, $msg, $key, true);
			return hash_equals($signature, $hash);
		}
		elseif($function == 'openssl')
		{
			$public_key = openssl_get_publickey($key);

			if(!$public_key)
			{
				throw new JsonWebTokenException('OpenSSL error: ' . openssl_error_string() );
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
			throw new JsonWebTokenException('OpenSSL error: ' . openssl_error_string() );
		}
		else
		{
			throw new JsonWebTokenException("Invalid algorithm function [$function].");
		}
	}

	/**
	 * Verifies payload[exp] and (payload[nbf] or payload[iat]) in payload of JWT token.
	 * @param int $leeway Small leeway, usually no more than a few minutes, to account for clock skew.
	 * @param bool $strong if TRUE then [exp] and [nbf] is require. Default FALSE.
	 * @return boolean
	 */
	public function verifyExpire($leeway = 0, $strong = false)
	{
		if(isset($this->payload['nbf']))
			$nbf = (int)$this->payload['nbf'];
		elseif(isset($this->payload['iat']))
			$nbf = (int)$this->payload['iat'];
		else
			$nbf = null;

		if(isset($this->payload['exp']))
			$exp = (int)$this->payload['exp'];
		else
			$exp = null;


		$now = time();
		$leeway = (int)$leeway;
		if($leeway < 0)
		{
			$leeway = 0;
		}

		if(is_null($nbf) and is_null($exp))
		{
			return !$strong;
		}
		elseif(is_null($exp))
		{
			if($strong)
			{
				return false;
			}
			else
			{
				return ( $now >= ($nbf - $leeway) );
			}
		}
		elseif(is_null($nbf))
		{
			if($strong)
			{
				return false;
			}
			else
			{
				return ( $now <= ($exp + $leeway) );
			}
		}
		else
		{
			return ( $now >= ($nbf - $leeway) ) and ( $now <= ($exp + $leeway) );
		}
	}

	/**
	 * Verifies the value of $aud in payload[aud].
	 * @param string $aud
	 * @return boolean
	 */
	public function verifyAudience($aud)
	{
		return in_array($aud, $this->getAudience());
	}



    /**
	 * Signs the string with an encryption algorithm.
	 *
     * @param string $msg The message to sign
     * @param string $key The secret key or private key content for openssl
     * @param string $alg The signing algorithm. See constantss ALG_.
     *
     * @return string Signature. For openssl signature is binary data!
     * @throws JsonWebTokenException
     */
    protected function sign($msg, $key, $alg)
    {
        if(is_null($alg))
		{
			throw new Exception('Signature encryption algorithm is undefined.');
		}

		if(!isset($this->supported_algs[$alg]))
		{
            throw new JsonWebTokenException('Signature encryption algorithm not supported.');
        }

		$key = (string)$key;

        list($function, $algorithm) = $this->supported_algs[$alg];

		if($function == 'hash_hmac')
		{
			return hash_hmac($algorithm, $msg, $key, true);
		}
		elseif($function == 'openssl')
		{
			$private_key = openssl_get_privatekey($key);

			if(!$private_key)
			{
				throw new JsonWebTokenException('OpenSSL error: ' . openssl_error_string() );
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
				throw new JsonWebTokenException("OpenSSL unable to sign data.");
			}
		}
    }

	/**
	 * Returns the encoded string header.payload.
	 * @return string
	 */
	protected function encryptedMessage()
	{
		$header_base64  = $this->base64Encode( $this->jsonEncode($this->header) );
		$payload_base64 = $this->base64Encode( $this->jsonEncode($this->payload) );

		return $header_base64.".".$payload_base64;
	}

	/**
	 * Create signed JWT token string.
	 * @param string $key Secret key or private key content for openssl.
	 * @return string
	 */
	public function create($key)
	{

		$this->payload['iat'] = time();

		$msg = $this->encryptedMessage();
		$alg = $this->getAlgorithm();
		$signature = $this->sign($msg, $key, $alg);
		$signature_base64 = $this->base64Encode($signature);
		return $msg.".".$signature_base64;
	}

	/**
	 * Returns token as array.
	 * @return array array(header, payload, signature)
	 */
	public function toArray()
	{
		return array(
			'header'    => $this->header,
			'payload'   => $this->payload,
			'signature' => $this->signature,
		);
	}


}


/**
 * An exception is thrown when the value of a variable differs from the expected value or type.
 */
class JsonWebTokenException extends \Exception{}

