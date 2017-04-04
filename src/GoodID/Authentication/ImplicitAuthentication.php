<?php

namespace GoodID\Authentication;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\Claim;
use GoodID\Helpers\Curve;
use GoodID\Helpers\JWKParameter;
use GoodID\Helpers\KeyType;
use GoodID\Helpers\RandomStringGenerator;
use GoodID\Helpers\Result;
use Jose\Loader;
use Jose\Object\JWK;
use Jose\Object\JWS;

/**
 * Class of GoodID implicit authentication method
 */
class ImplicitAuthentication extends AbstractAuthentication
{
    /**
     * @param string $jwsIdToken
     * @param string $jwsUserInfo
     * @param string $receivedState
     *
     * @return Result
     */
    public function getClaims($jwsIdToken, $jwsUserInfo, $receivedState)
    {
        $idTokenClaims = $this->getIdTokenClaims($jwsIdToken, $receivedState)->toArray();
        $userinfoClaims = $this->getUserInfoClaims($jwsUserInfo)->toArray();

        if (!isset($idTokenClaims[Claim::NAME_SUBJECT])
            || !isset($userinfoClaims[Claim::NAME_SUBJECT])
            || $idTokenClaims[Claim::NAME_SUBJECT] !== $userinfoClaims[Claim::NAME_SUBJECT]) {
            throw new ValidationException('The idToken and userinfo data belong to different users.');
        }

        return new Result(array_merge($idTokenClaims, $userinfoClaims));
    }

    /**
     * @param string $jwsUserInfo
     *
     * @return Result
     */
    public function getUserInfoClaims($jwsUserInfo)
    {
        // @TODO validate if jws is a userInfo JWS

        $claims = $this->getVerifiedClaims($jwsUserInfo);

        if (isset($claims[Claim::NAME_CLAIMS][Claim::NAME_EMAIL_VERIFIED])
            && isset($claims[Claim::NAME_CLAIMS][Claim::NAME_GOODID_EMAIL_CERT])) {
            unset($claims[Claim::NAME_CLAIMS][Claim::NAME_GOODID_EMAIL_CERT]);
        }

        return new Result($claims);
    }

    /**
     * @param string $jwsIdToken
     * @param string $receivedState
     *
     * @return Result
     *
     * @throws ValidationException
     */
    public function getIdTokenClaims($jwsIdToken, $receivedState)
    {
        // @TODO validate if jws is an idToken JWS

        $storedStates = $this->sessionDataHandler->get(self::SESSION_KEY_STATE);
        if (is_null($storedStates) || !in_array($receivedState, $storedStates)) {
            throw new ValidationException('The received state is invalid.');
        }

        // Remove all the stored state parameters from session.
        $this->sessionDataHandler->remove(self::SESSION_KEY_STATE);

        $claims = $this->getVerifiedClaims($jwsIdToken);

        if (!isset($claims[Claim::NAME_EXPIRATION_TIME])
            || !is_int($claims[Claim::NAME_EXPIRATION_TIME])
            || time() >= $claims[Claim::NAME_EXPIRATION_TIME]
        ) {
            throw new ValidationException("Expired token.");
        }

        $storedNonces = $this->sessionDataHandler->get(self::SESSION_KEY_NONCE);
        if (!isset($claims[Claim::NAME_NONCE])
            || is_null($storedNonces)
            || !in_array($claims[Claim::NAME_NONCE], $storedNonces)
        ) {
            throw new ValidationException("The received nonce is invalid.");
        }

        // Remove all the stored nonce parameters from session.
        $this->sessionDataHandler->remove(self::SESSION_KEY_NONCE);

        // Remove `claims` because personal data can be only requested in userinfo
        if (isset($claims[Claim::NAME_CLAIMS])) {
            unset($claims[Claim::NAME_CLAIMS]);
        }

        return new Result($claims);
    }

    /**
     * @return string
     */
    public function generateState()
    {
        $random = RandomStringGenerator::getPseudoRandomString(32);
        $this->sessionDataHandler->set(self::SESSION_KEY_STATE, $random);

        return $random;
    }

    /**
     * @return string
     */
    public function generateNonce()
    {
        $random = RandomStringGenerator::getPseudoRandomString(32);
        $this->sessionDataHandler->set(self::SESSION_KEY_NONCE, $random);

        return $random;
    }

    /**
     * @param JWS $jws
     *
     * @return JWK
     *
     * @throws ValidationException
     */
    private function getJwkFromJws(JWS $jws)
    {
        if (!$jws->hasClaim(Claim::NAME_SUB_JWK)) {
            throw new ValidationException('Missing sub_jwk.');
        }

        try {
            $jwkArray = (array) $jws->getClaim(Claim::NAME_SUB_JWK);

            if (!isset($jwkArray[JWKParameter::PARAM_KEY_TYPE])
                || !isset($jwkArray[JWKParameter::PARAM_CURVE])
                || $jwkArray[JWKParameter::PARAM_KEY_TYPE] !== KeyType::TYPE_EC
                || $jwkArray[JWKParameter::PARAM_CURVE] !== Curve::CURVE_P256
            ) {
                throw new \Exception();
            }

            return new JWK($jwkArray);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid sub_jwk format.');
        }
    }

    /**
     * @param string $jwsString
     *
     * @return array
     *
     * @throws ValidationException
     */
    private function getVerifiedClaims($jwsString)
    {
        $loader = new Loader();

        try {
            $unverifiedJws = $loader->load($jwsString);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid JWS string.');
        }

        $jwk = $this->getJwkFromJws($unverifiedJws);

        try {
            $verifiedJws = $loader->loadAndVerifySignatureUsingKey($jwsString, $jwk, [self::ALGO_ES256]);
            $claims = $verifiedJws->getClaims();
        } catch (\Exception $e) {
            throw new ValidationException('Invalid signature.');
        }

        // Verify that sub_jwk corresponds to sub
        if (!isset($claims[Claim::NAME_SUBJECT]) || $claims[Claim::NAME_SUBJECT] !== $jwk->thumbprint("sha256")) {
            throw new \Exception('Invalid signature: sub vs sub_jwk mismatch.');
        }

        // Verify issuer
            if (!isset($claims[Claim::NAME_ISSUER]) || $claims[Claim::NAME_ISSUER] !== self::ISS_GOODID) {
                throw new \Exception("Invalid issuer.");
            }

        // Verify audience
        if (!isset($claims[Claim::NAME_AUDIENCE]) || $claims[Claim::NAME_AUDIENCE] !== $this->clientId) {
            throw new ValidationException("Invalid audience.");
        }

        return $claims;
    }
}
