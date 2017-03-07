<?php

namespace GoodID\Authentication;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\JWT\Claims;
use GoodID\Helpers\JWT\JWT;
use JWX\JWA\JWA;
use JWX\JWK\JWK;
use JWX\JWK\Parameter\CurveParameter;
use JWX\JWK\Parameter\JWKParameter;
use JWX\JWK\Parameter\KeyTypeParameter;
use JWX\JWT\Claim\RegisteredClaim;
use JWX\JWT\Parameter\JWTParameter;
use JWX\JWT\ValidationContext;
use JWX\Util\Base64;
use Lcobucci\JWT\Parser;

/**
 * Class of GoodID implicit authentication method
 */
class ImplicitAuthentication extends AbstractAuthentication
{
    /**
     * @param string $jwsIdToken
     * @param string $jwsUserInfo
     *
     * @return Claims
     */
    public function getClaims($jwsIdToken, $jwsUserInfo)
    {
        return new Claims(...array_values(array_merge(
            $this->getIdTokenClaims($jwsIdToken)->all(),
            $this->getUserInfoClaims($jwsUserInfo)->all())
        ));
    }

    /**
     * @param string $jwsUserInfo
     *
     * @return Claims
     */
    public function getUserInfoClaims($jwsUserInfo)
    {
        // @TODO validate if jws is a userInfo JWS

        return $this->getVerifiedClaims($jwsUserInfo);
    }

    /**
     * @param string $jwsIdToken
     *
     * @return Claims
     *
     * @throws ValidationException
     * @throws \Exception
     */
    public function getIdTokenClaims($jwsIdToken)
    {
        // @TODO validate if jws is an idToken JWS

        $claims = $this->getVerifiedClaims($jwsIdToken);

        // Verify expiration time
        if (!$claims->has(RegisteredClaim::NAME_EXPIRATION_TIME)
            || !is_int($claims->get(RegisteredClaim::NAME_EXPIRATION_TIME)->value())
            || time() >= $claims->get(RegisteredClaim::NAME_EXPIRATION_TIME)->value()
        ) {
            throw new ValidationException("Expired token.");
        }

        // Remove `claims` because personal data can be only requested in userinfo
        if ($claims->has('claims')) {
            $claimsArray = $claims->toArray();
            unset($claimsArray['claims']);

            $claims = Claims::fromJSON(json_encode($claimsArray));
        }

        return $claims;
    }

    /**
     * @param JWK $jwk
     *
     * @return string
     *
     * @throws ValidationException
     */
    private function jwkThumbprint(JWK $jwk)
    {
        if (!in_array(self::HASH_SHA256, hash_algos())) {
            throw new ValidationException('sha256 hash is not supported in your php');
        }

        $values = array_intersect_key($jwk->toArray(), array_flip([
            JWKParameter::PARAM_KEY_TYPE,
            JWKParameter::PARAM_MODULUS,
            JWKParameter::PARAM_EXPONENT,
            JWKParameter::PARAM_CURVE,
            JWKParameter::PARAM_X_COORDINATE,
            JWKParameter::PARAM_Y_COORDINATE,
            JWKParameter::PARAM_KEY_VALUE
        ]));

        ksort($values);
        $input = json_encode($values);

        return Base64::urlEncode(hash(self::HASH_SHA256, $input, true));
    }

    /**
     * @param string $jws
     *
     * @return JWT
     */
    private function getJwtFromJws($jws)
    {
        try {
            return new JWT($jws);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid JWS string.');
        }
    }

    /**
     * @param string $jws
     *
     * @return JWK
     *
     * @throws ValidationException
     * @throws \Exception
     */
    private function getJwkFromJws($jws)
    {
        try {
            $unverifiedJWS = (new Parser())->parse((string) $jws);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid JWS string.');
        }

        if (!$unverifiedJWS->hasClaim(RegisteredClaim::NAME_SUB_JWK)) {
            throw new ValidationException('Missing sub_jwk.');
        }

        try {
            $jwkArray = (array) $unverifiedJWS->getClaim(RegisteredClaim::NAME_SUB_JWK);

            if (!isset($jwkArray[JWKParameter::PARAM_KEY_TYPE])
                || !isset($jwkArray[JWKParameter::PARAM_CURVE])
                || $jwkArray[JWKParameter::PARAM_KEY_TYPE] !== KeyTypeParameter::TYPE_EC
                || $jwkArray[JWKParameter::PARAM_CURVE] !== CurveParameter::CURVE_P256
            ) {
                throw new \Exception();
            }

            return JWK::fromArray($jwkArray);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid sub_jwk format.');
        }
    }

    /**
     * @param string $jws
     *
     * @return Claims
     *
     * @throws ValidationException
     */
    private function getVerifiedClaims($jws)
    {
        $jwk = $this->getJwkFromJws($jws);
        $jwt = $this->getJwtFromJws($jws);
        
        try {
            $validationContext = ValidationContext::fromJWK($jwk)->withReferenceTime(null);

            $claims = $jwt->claims($validationContext);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid signature.');
        }

        $header = $jwt->header();
        if (!$header->has(JWTParameter::PARAM_ALGORITHM) || $header->get(JWTParameter::PARAM_ALGORITHM)->value() !== JWA::ALGO_ES256) {
            throw new ValidationException('Invalid algorithm requested in token.');
        }
        
        // Verify that sub_jwk corresponds to sub
        $jwkThumbprint = $this->jwkThumbprint($jwk);
        if (!$claims->has(RegisteredClaim::NAME_SUBJECT)
            || $claims->get(RegisteredClaim::NAME_SUBJECT)->value() !== $jwkThumbprint
        ) {
            throw new ValidationException('Invalid signature: sub vs sub_jwk mismatch.');
        }

        // Verify issuer
        if (!$claims->has(RegisteredClaim::NAME_ISSUER) || $claims->get(RegisteredClaim::NAME_ISSUER)->value() !== self::ISS_GOODID) {
            throw new ValidationException("Invalid issuer.");
        }

        // Verify audience
        if (!$claims->has(RegisteredClaim::NAME_AUDIENCE) || !in_array($this->clientId, $claims->get(RegisteredClaim::NAME_AUDIENCE)->value())) {
            throw new ValidationException("Invalid audience.");
        }

        return $claims;
    }
}
