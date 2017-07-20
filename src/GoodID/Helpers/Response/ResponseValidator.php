<?php
/**
 * Copyright 2017 ID&Trust, Ltd.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to
 * use, copy, modify, and distribute this software in source code or binary form
 * for use in connection with the web services and APIs provided by ID&Trust.
 *
 * As with any software that integrates with the GoodID platform, your use
 * of this software is subject to the GoodID Terms of Service
 * (https://goodid.net/docs/tos).
 * This copyright notice shall be included in all copies or substantial portions
 * of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

namespace GoodID\Helpers\Response;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\Claim;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\ECPublicKey;
use GoodID\Helpers\Logic\LogicEvaluator;
use GoodID\Helpers\StateNonceHandler;

/**
 * ResponseValidator class
 *
 * Validates the user data returned from the GoodID Token and the Userinfo endpoints
 */
class ResponseValidator
{

    /**
     * Claim name: E-mail verified
     */
    const CLAIM_NAME_EMAIL_VERIFIED = "email_verified";

    /**
     * Claim name: GoodID e-mail certificate
     */
    const CLAIM_NAME_GOODID_EMAIL_CERT = "email_cert";

    /**
     * Claim name: Nonce
     */
    const CLAIM_NAME_NONCE = "nonce";

    /**
     * Claim name: State
     */
    const CLAIM_NAME_STATE = "state";

    /**
     * The maximum lifetime of a token in seconds
     * The value is set to 61 days
     */
    const TOKEN_MAX_LIFETIME_SECONDS = 5270400;

    /**
     * @var string
     */
    private $clientId;

    /**
     * @var GoodIDServerConfig
     */
    private $goodIDServerConfig;

    /**
     * @var StateNonceHandler
     */
    private $stateNonceHandler;

    /**
     * ResponseValidator constructor
     *
     * @param string $clientId Client ID
     * @param GoodIDServerConfig $goodIDServerConfig GoodIDServerConfig
     * @param StateNonceHandler $stateNonceHandler
     */
    public function __construct(
        $clientId,
        GoodIDServerConfig $goodIDServerConfig,
        StateNonceHandler $stateNonceHandler
    ) {
        $this->clientId = $clientId;
        $this->goodIDServerConfig = $goodIDServerConfig;
        $this->stateNonceHandler = $stateNonceHandler;
    }

    /**
     * Validates if the two tokens correspond to the same user
     *
     * @param array $idToken Id Token as array
     * @param array $userinfo Userinfo as array
     *
     * @throws ValidationException on error
     */
    public function validateTokensBelongTogether(array $idToken, array $userinfo)
    {
        if (!isset($idToken[Claim::NAME_SUBJECT])
            || !isset($userinfo[Claim::NAME_SUBJECT])
            || $idToken[Claim::NAME_SUBJECT] !== $userinfo[Claim::NAME_SUBJECT]
        ) {
            throw new ValidationException('The idToken and userinfo data belong to different users.');
        }
    }

    /**
     * Validates and decodes Userinfo
     *
     * @param string $jwsUserInfo Userinfo as compact JWS
     *
     * @return array Userinfo as array
     */
    public function validateUserInfo($jwsUserInfo)
    {
        $claims = $this->validate($jwsUserInfo);

        if (isset($claims[Claim::NAME_CLAIMS][self::CLAIM_NAME_EMAIL_VERIFIED])
            && isset($claims[Claim::NAME_CLAIMS][self::CLAIM_NAME_GOODID_EMAIL_CERT])
        ) {
            unset($claims[Claim::NAME_CLAIMS][self::CLAIM_NAME_GOODID_EMAIL_CERT]);
        }

        return $claims;
    }

    /**
     * Validates the state parameter
     *
     * @param string $receivedState Received state
     *
     * @throws ValidationException on error
     */
    public function validateState($receivedState)
    {
        if (!$this->stateNonceHandler->validateState($receivedState)) {
            throw new ValidationException("The received state is invalid.");
        }
    }

    /**
     * Validates and decodes Id Token
     *
     * @param string $jwsIdToken Id Token as a compact JWS
     * @param int $goodIDServerTime GoodID Server time as a Unix timestamp
     *
     * @return array Id Token as an array
     *
     * @throws ValidationException on error
     */
    public function validateIdToken($jwsIdToken, $goodIDServerTime)
    {
        $claims = $this->validate($jwsIdToken);

        if (!isset($claims[Claim::NAME_EXPIRATION_TIME])
            || !is_int($claims[Claim::NAME_EXPIRATION_TIME])
            || $claims[Claim::NAME_EXPIRATION_TIME] <= $goodIDServerTime
            || $claims[Claim::NAME_EXPIRATION_TIME] >= $goodIDServerTime + self::TOKEN_MAX_LIFETIME_SECONDS
        ) {
            throw new ValidationException("Expired token.");
        }

        if (!isset($claims[self::CLAIM_NAME_NONCE])
            || !$this->stateNonceHandler->validateNonce($claims[self::CLAIM_NAME_NONCE])
        ) {
            throw new ValidationException("The received nonce is invalid.");
        }

        // Remove `claims` because personal data can be only requested in userinfo
        if (isset($claims[Claim::NAME_CLAIMS])) {
            unset($claims[Claim::NAME_CLAIMS]);
        }

        return $claims;
    }

    /**
     * Validates and decodes a compact JWS token
     *
     * @param string $jwsString Compact JWS token
     *
     * @return array Token as array
     *
     * @throws ValidationException on error
     */
    private function validate($jwsString)
    {
        $claims = ECPublicKey::verifySelfSignedCompactJws($jwsString);

        // Verify issuer
        if (!isset($claims[Claim::NAME_ISSUER]) || $claims[Claim::NAME_ISSUER] !== $this->goodIDServerConfig->getIssuerUri()) {
            throw new ValidationException("Invalid issuer.");
        }

        // Verify audience
        if (!isset($claims[Claim::NAME_AUDIENCE]) || $claims[Claim::NAME_AUDIENCE] !== $this->clientId) {
            throw new ValidationException("Invalid audience.");
        }

        return $claims;
    }

    /**
     * Validates that the given userinfo is a valid response for the requestedClaims.
     * This must be called after other validations
     *
     * @param array $requestedClaims Requested claims
     * @param array $userinfo Userinfo
     *
     * @throws ValidationException on error
     */
    public function validateMatchingResponse(array $requestedClaims, array $userinfo)
    {
        $rules = [];
        if (isset($requestedClaims['rules'])) {
            if (!is_array($requestedClaims['rules'])) {
                throw new ValidationException("Rules must be array (logic expression).");
            }
            if (is_array($requestedClaims['rules'])) {
                $rules =& $requestedClaims['rules'];
            }
        }
        if (isset($requestedClaims['userinfo'])) {
            $userinfoClaims = isset($userinfo['claims']) ? $userinfo['claims'] : [];
            $this->validateMatchingResponseForToken(
                $requestedClaims['userinfo'],
                $userinfoClaims,
                $rules
            );
        }
    }

    /**
     * Validates that the requested essential claims are in the response,
     * taking conditionals and special cases into account
     *
     * @param array $request Request
     * @param array $response Response
     * @param array $rules Rules
     *
     * @throws ValidationException
     */
    private function validateMatchingResponseForToken(array $request, array $response, array $rules)
    {
        $logicEvaluator = new LogicEvaluator($rules, $response);

        foreach ($request as $claimName => $valueInRequest) {
            if (!$this->isVerificationClaim($claimName)) {
                continue;
            }

            $enabled = $this->getBoolValue($valueInRequest, 'conditional', true, $logicEvaluator);
            // If value=false is given, we accept both true and false.
            // It would make no sense to ask for stricly unverified e-mail or phone-number.
            // $essential is not considered for verification claims
            $mustBeVerified = $this->getBoolValue($valueInRequest, 'value', false, $logicEvaluator);
            $valueInResponse = $this->getClaimValue($response, $claimName);

            $baseClaimName = substr($claimName, 0, strlen($claimName) - strlen('_verified'));
            $baseClaimValueInRequest = isset($request[$baseClaimName]) ? $request[$baseClaimName] : [];
            $isBaseClaimEnabled = $this->getBoolValue($baseClaimValueInRequest, 'conditional', true, $logicEvaluator);
            $baseClaimValueInResponse = $this->getClaimValue($response, $claimName);
            $isBaseClaimSet = !is_null($baseClaimValueInResponse);
            $isBaseClaimEssential = $this->getBoolValue($baseClaimValueInRequest, 'essential', false, $logicEvaluator);

            if (!$isBaseClaimEnabled && $isBaseClaimSet) {
                throw new ValidationException("Verifiable claim $baseClaimName disabled by conditional, but set.");
            }

            if ($isBaseClaimEssential && !$isBaseClaimSet) {
                throw new ValidationException("Verifiable claim $baseClaimName essential, but missing.");
            }

            if ($enabled && $isBaseClaimEnabled && $isBaseClaimSet) {
                if (!is_bool($valueInResponse)) {
                    throw new ValidationException("Verification claim $claimName missing or has an invalid type.");
                }

                if ($mustBeVerified && $valueInResponse !== true) {
                    throw new ValidationException("Verification claim $claimName not true.");
                }
            }
        }
    }

    /**
     * Get bool value from request
     *
     * @param mixed $valueInRequest
     * @param string $attribute
     * @param bool $defaultValue
     * @param LogicEvaluator $logicEvaluator
     *
     * @return bool
     *
     * @throws ValidationException on bad type
     */
    private function getBoolValue($valueInRequest, $attribute, $defaultValue, LogicEvaluator $logicEvaluator)
    {
        if (is_array($valueInRequest) && isset($valueInRequest[$attribute])) {
            $value = $logicEvaluator->evaluate($valueInRequest[$attribute]);
            if (!is_bool($value)) {
                throw new ValidationException($attribute . ' can not be evaluated to bool.');
            }

            return $value;
        }

        return $defaultValue;
    }

    /**
     * Is verification claim
     *
     * @param string $claimName Claim name
     *
     * @return bool isVerificationClaim
     */
    private function isVerificationClaim($claimName)
    {
        return $this->endsWith($claimName, "_verified");
    }

    /**
     * Does the string end with the given ending?
     *
     * @param string $string String
     * @param string $ending Ending
     *
     * @return boolean endsWith
     */
    private function endsWith($string, $ending)
    {
        $length = strlen($ending);
        if ($length == 0) {
            return true;
        }

        return (substr($string, -$length) === $ending);
    }

    /**
     * Get claim value
     *
     * @param array $claims
     * @param string $claimName
     *
     * @return mixed
     */
    private function getClaimValue(array $claims, $claimName)
    {
        $components = explode('.', $claimName);
        $current =& $claims;

        foreach ($components as $component) {
            if (isset($current[$component])) {
                $current =& $current[$component];
            } else {
                return null;
            }
        }

        return $current;
    }
}
