<?php

namespace GoodID\Helpers\JWT;

use JWX\JWK\JWKSet;
use JWX\JWS\JWS;
use JWX\JWT\Exception\ValidationException;
use JWX\JWT\JWT as ParentJwt;
use JWX\JWT\ValidationContext;

class JWT extends ParentJwt
{
    /**
     * Get claims from the JWT.
     *
     * Claims shall be validated according to given validation context.
     * Validation context must contain all the necessary keys for the signature
     * validation and/or content decryption.
     *
     * If validation context contains only one key, it shall be used explicitly.
     * If multiple keys are provided, they must contain a JWK ID parameter for
     * the key identification.
     *
     * @param ValidationContext $ctx
     * @throws ValidationException If signature is invalid, or decryption fails,
     *         or claims validation fails.
     * @throws \RuntimeException For generic errors
     *
     * @return Claims
     */
    public function claims(ValidationContext $ctx)
    {
        // check signature or decrypt depending on the JWT type.
        if ($this->isJWS()) {
            $payload = self::_validatedPayloadFromJWS($this->JWS(), $ctx);
        } else {
            throw new \Exception('This is not a JWS.');
        }
        // if JWT contains a nested token
        if ($this->isNested()) {
            return $this->_claimsFromNestedPayload($payload, $ctx);
        }

        // decode claims and validate
        $claims = Claims::fromJSON($payload);
        $ctx->validate($claims);

        return $claims;
    }

    /**
     * Get validated payload from JWS.
     *
     * @param JWS $jws JWS
     * @param ValidationContext $ctx Validation context
     *
     * @throws ValidationException If signature validation fails
     *
     * @return string
     */
    private static function _validatedPayloadFromJWS(
        JWS $jws,
        ValidationContext $ctx
    ) {
        // if JWS is unsecured
        if ($jws->isUnsecured()) {
            return self::_validatedPayloadFromUnsecuredJWS($jws, $ctx);
        }

        return self::_validatedPayloadFromSignedJWS($jws, $ctx->keys());
    }

    /**
     * Get validated payload from an unsecured JWS.
     *
     * @param JWS $jws JWS
     * @param ValidationContext $ctx Validation context
     *
     * @throws ValidationException If unsecured JWT's are not allowed, or JWS
     *         token is malformed
     *
     * @return string
     */
    private static function _validatedPayloadFromUnsecuredJWS(
        JWS $jws,
        ValidationContext $ctx
    ) {
        if (!$ctx->isUnsecuredAllowed()) {
            throw new ValidationException("Unsecured JWS not allowed.");
        }
        if (!$jws->validate(new NoneAlgorithm())) {
            throw new ValidationException("Malformed unsecured token.");
        }

        return $jws->payload();
    }

    /**
     * Get validated payload from a signed JWS.
     *
     * @param JWS $jws JWS
     * @param JWKSet $keys Set of allowed keys for the signature validation
     *
     * @throws ValidationException If validation fails
     *
     * @return string
     */
    private static function _validatedPayloadFromSignedJWS(
        JWS $jws,
        JWKSet $keys
    ) {
        try {
            // explicitly defined key
            if (1 == count($keys)) {
                $valid = $jws->validateWithJWK($keys->first());
            } else {
                $valid = $jws->validateWithJWKSet($keys);
            }
        } catch (\RuntimeException $e) {
            throw new ValidationException("JWS validation failed.", null, $e);
        }

        if (!$valid) {
            throw new ValidationException("JWS signature is invalid.");
        }

        return $jws->payload();
    }
}
