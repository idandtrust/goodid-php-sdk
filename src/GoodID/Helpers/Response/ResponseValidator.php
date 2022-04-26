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
use GoodID\Helpers\Logic\LogicEvaluator;

/**
 * ResponseValidator class
 *
 * Validates the user data returned from the GoodID Token and the Userinfo endpoints
 */
class ResponseValidator
{
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

            $rules =& $requestedClaims['rules'];
        }
        if (isset($requestedClaims['userinfo']) && !is_object($requestedClaims['userinfo'])) {
            $this->validateMatchingResponseForToken(
                $requestedClaims['userinfo'],
                $userinfo,
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
            $baseClaimValueInResponse = $this->getClaimValue($response, $baseClaimName);
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
