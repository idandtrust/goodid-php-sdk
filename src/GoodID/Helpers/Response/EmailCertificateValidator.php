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

use GoodID\Exception\GoodIDException;
use GoodID\Exception\ValidationException;
use GoodID\Helpers\Claim;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;
use Jose\Loader;
use Jose\Object\JWK;

/**
 * EmailCertificateValidator class
 *
 */
class EmailCertificateValidator
{
    const CLAIM_NAME_EMAIL = "email";
    const CLAIM_NAME_EMAIL_VERIFIED = "email_verified";
    const CLAIM_NAME_EMAIL_CERT = "email_cert";

    const NAME_ALG = "alg";
    const NAME_CERTS = "certs";
    const NAME_HASH = "hash";
    const NAME_ID = "id";
    const NAME_JWK = "jwk";
    const NAME_JWKS_URI = "jku";
    const NAME_JWK_THUMBPRINT = "jwk_tp";
    const NAME_KEYS = "keys";
    const NAME_KEY_ID = "kid";
    const NAME_SIGN = "sign";
    const NAME_TYPE = "typ";

    const HASH_ALG_SHA256 = "sha256";
    const ID_EMAIL = "email";
    const JWK_ALG_ES256 = "ES256";
    const TYPE_GOODID_VERIFIED_ATTRIBUTE = "gid.ver.attr";
    const KEY_ID_PREFIX_GOODID_VERIFIED_ATTRIBUTE = "gid.ver.attr.";

    const MAX_CERT_COUNT = 1;

    /**
     *
     * @var GoodIDServerConfig
     */
    private $goodIDServerConfig;

    /**
     *
     * @param GoodIDServerConfig $goodIDServerConfig
     */
    public function __construct(GoodIDServerConfig $goodIDServerConfig)
    {
        $this->goodIDServerConfig = $goodIDServerConfig;
    }

    /**
     *
     * @param array $userInfo User info
     * @throws ValidationException
     */
    public function validateUserInfo(array $userInfo)
    {
        if (!isset($userInfo[Claim::NAME_CLAIMS][self::CLAIM_NAME_EMAIL_VERIFIED])
            || !$userInfo[Claim::NAME_CLAIMS][self::CLAIM_NAME_EMAIL_VERIFIED]
        ) {
            return;
        }

        $claims = $userInfo[Claim::NAME_CLAIMS];

        if (isset($claims[self::CLAIM_NAME_EMAIL]) && is_string($claims[self::CLAIM_NAME_EMAIL])) {
            $email = $claims[self::CLAIM_NAME_EMAIL];
        } else {
            throw new ValidationException('E-mail must be string.');
        }

        if (isset($claims[self::CLAIM_NAME_EMAIL_CERT]) && is_array($claims[self::CLAIM_NAME_EMAIL_CERT])) {
            $emailCert = $claims[self::CLAIM_NAME_EMAIL_CERT];
        } else {
            throw new ValidationException('E-mail cert must be array.');
        }

        if (isset($emailCert[self::NAME_SIGN]) && is_string($emailCert[self::NAME_SIGN])) {
            $signJws = $emailCert[self::NAME_SIGN];
        } else {
            throw new ValidationException('E-mail cert sign must be string.');
        }

        if (isset($emailCert[self::NAME_JWK]) && is_array($emailCert[self::NAME_JWK])) {
            $jwkAsArray = $emailCert[self::NAME_JWK];
        } else {
            throw new ValidationException('E-mail cert jwk must be array.');
        }

        $jwk = $this->jwkFromArray($jwkAsArray);

        if (is_null($jwk)) {
            throw new ValidationException('E-mail cert jwk can not be loaded.');
        }

        $jwkThumbprint = $jwk->thumbprint(self::HASH_ALG_SHA256);

        list($signHeader, $signPayload) = $this->extractJwtHeaderAndPayloadUnverified($signJws);

        if (is_null($signHeader) || is_null($signPayload)) {
            throw new ValidationException('E-mail cert sign can not be loaded.');
        }

        if (!isset($signHeader[self::NAME_ALG]) || $signHeader[self::NAME_ALG] !== self::JWK_ALG_ES256) {
            throw new ValidationException('E-mail cert sign header has invalid alg.');
        }

        // Connection between sign and jwk
        if (!$this->isJwsSignatureValid($signJws, $jwk)) {
            throw new ValidationException('E-mail cert sign is not (validly) signed with the the e-mail cert jwk.');
        }

        if (isset($userInfo[Claim::NAME_SUBJECT]) && is_string($userInfo[Claim::NAME_SUBJECT])) {
            $subFromUserInfo = $userInfo[Claim::NAME_SUBJECT];
        } else {
            throw new ValidationException('Sub must be string.');
        }

        // Connection between sign and sub
        if (!isset($signPayload[Claim::NAME_SUBJECT]) || $signPayload[Claim::NAME_SUBJECT] !== $subFromUserInfo) {
            throw new ValidationException('E-mail cert sign was not made for this subject.');
        }

        if (!isset($signPayload[self::NAME_ID]) || $signPayload[self::NAME_ID] !== self::ID_EMAIL) {
            throw new ValidationException('E-mail cert sign was not made for an e-mail.');
        }

        $emailHash = $this->urlsafeBase64Hash($email);

        // Connection between sign and email
        if (!isset($signPayload[self::NAME_HASH]) || $signPayload[self::NAME_HASH] !== $emailHash) {
            throw new ValidationException('E-mail cert sign was not made for this e-mail.');
        }

        if (isset($emailCert[self::NAME_CERTS])
            && $this->isSequentialArray($emailCert[self::NAME_CERTS])
            && count($emailCert[self::NAME_CERTS]) >= 1
        ) {
            $certs = $emailCert[self::NAME_CERTS];
        } else {
            throw new ValidationException('E-mail certs must be a sequential array of at least one elem.');
        }

        $goodIdKeys = $this->getAssocArrayOfKeysFromJwksUri();

        $hasGoodCert = false;
        $exceptionMessages = '';
        for ($i = 0; $i < min(count($certs), self::MAX_CERT_COUNT); $i++) {
            $certJws = $certs[$i];
            try {
                $this->validateEmailCert($certJws, $emailHash, $jwkThumbprint, $goodIdKeys);
                $hasGoodCert = true;
                break;
            } catch (ValidationException $e) {
                $exceptionMessages .= $e->getMessage() . ', ';
            }
        }

        if (!$hasGoodCert) {
            throw new ValidationException('No cert was valid: ' . $exceptionMessages);
        }

        // Seems valid.
    }

    /**
     *
     * @param string $certJws
     * @param string $expectedEmailHash
     * @param string $expectedJwkThumbprint
     * @param array $goodIdJwks
     * @throws ValidationException
     */
    private function validateEmailCert($certJws, $expectedEmailHash, $expectedJwkThumbprint, $goodIdJwks)
    {
        if (!is_string($certJws)) {
            throw new ValidationException("E-mail cert JWS must be string");
        }

        list($certHeader, $certPayload) = $this->extractJwtHeaderAndPayloadUnverified($certJws);

        if (is_null($certHeader) || is_null($certPayload)) {
            throw new ValidationException("E-mail cert JWS can not be loaded");
        }

        if (!isset($certHeader[self::NAME_ALG]) || $certHeader[self::NAME_ALG] !== self::JWK_ALG_ES256) {
            throw new ValidationException("E-mail cert header has invalid alg");
        }

        if (!isset($certHeader[self::NAME_TYPE]) || $certHeader[self::NAME_TYPE] !== self::TYPE_GOODID_VERIFIED_ATTRIBUTE) {
            throw new ValidationException("E-mail cert is not a GoodID verified attribute");
        }

        if (!isset($certHeader[self::NAME_JWKS_URI]) || $certHeader[self::NAME_JWKS_URI] !== $this->goodIDServerConfig->getJwksUri()) {
            throw new ValidationException("E-mail cert has invalid JWKS URI");
        }

        if (isset($certHeader[self::NAME_KEY_ID])
            && is_string($certHeader[self::NAME_KEY_ID])
            && $this->startsWith($certHeader[self::NAME_KEY_ID], self::KEY_ID_PREFIX_GOODID_VERIFIED_ATTRIBUTE)
        ) {
            $keyId = $certHeader[self::NAME_KEY_ID];
        } else {
            throw new ValidationException(
                "E-mail cert key id must be string, starting with "
                . self::KEY_ID_PREFIX_GOODID_VERIFIED_ATTRIBUTE
            );
        }

        if (isset($goodIdJwks[$keyId])) {
            $goodIdJwkArray = $goodIdJwks[$keyId];
        } else {
            throw new ValidationException("Key id $keyId not found on GoodID jwks uri");
        }

        $goodIdJwk = $this->jwkFromArray($goodIdJwkArray);

        if (is_null($goodIdJwk)) {
            throw new ValidationException('GoodID jwk can not be loaded');
        }

        // Connection between cartificate and GoodID
        if (!$this->isJwsSignatureValid($certJws, $goodIdJwk)) {
            throw new ValidationException("E-mail cert signature is invalid");
        }

        if (!isset($certPayload[self::NAME_ID]) || $certPayload[self::NAME_ID] !== self::ID_EMAIL) {
            throw new ValidationException('E-mail cert was not made for an e-mail');
        }

        // Connection between certificate and email
        if (!isset($certPayload[self::NAME_HASH]) || $certPayload[self::NAME_HASH] !== $expectedEmailHash) {
            throw new ValidationException('E-mail cert was not made for the given e-mail');
        }

        // Connection between certificate and jwk
        if (!isset($certPayload[self::NAME_JWK_THUMBPRINT]) || $certPayload[self::NAME_JWK_THUMBPRINT] !== $expectedJwkThumbprint) {
            throw new ValidationException('E-mail cert was not made for the given e-mail cert jwk');
        }

        // Seems valid.
    }

    /**
     *
     * @return array
     * @throws ValidationException
     */
    private function getAssocArrayOfKeysFromJwksUri()
    {
        $response = (new HttpRequest($this->goodIDServerConfig->getJwksUri()))->get();

        if ($response->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
            throw new ValidationException('GoodID jwksuri unreachable');
        }

        try {
            $jwks = $response->getBodyJsonDecoded();
        } catch (GoodIDException $e) {
            throw new ValidationException('GoodID jwksuri content is not valid JSON');
        }

        if (!is_array($jwks)) {
            throw new ValidationException('GoodID jwksuri content is not an object');
        }

        if (isset($jwks[self::NAME_KEYS]) && is_array($jwks[self::NAME_KEYS])) {
            $keys = $jwks[self::NAME_KEYS];
        } else {
            throw new ValidationException("GoodID jwksuri must have '". self::NAME_KEYS ."' member, with type 'array'");
        }

        $goodIDJwks = [];

        foreach ($keys as $key) {
            if (isset($key[self::NAME_KEY_ID]) && (is_string($key[self::NAME_KEY_ID]) || is_int($key[self::NAME_KEY_ID]))) {
                $keyId = (string) $key[self::NAME_KEY_ID];
            } else {
                throw new ValidationException("GoodID jwksuri contains key without " . self::NAME_KEY_ID . " with type string or int");
            }

            $goodIDJwks[$keyId] = $key;
        }

        return $goodIDJwks;
    }

    /**
     *
     * @param array $jwkArray
     * @return JWK|null
     */
    private function jwkFromArray($jwkArray)
    {
        try {
            return new JWK($jwkArray);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     *
     * @param string $jwtString
     * @return array
     */
    private function extractJwtHeaderAndPayloadUnverified($jwtString)
    {
        if (!is_string($jwtString)) {
            return [null, null];
        }

        $parts = explode('.', $jwtString);

        if (count($parts) !== 2 && count($parts) !== 3) {
            return [null, null];
        }

        $jsonHeader = base64_decode($parts[0]);
        $jsonPayload = base64_decode($parts[1]);

        if ($jsonHeader === false || $jsonPayload === false) {
            return [null, null];
        }

        $header = json_decode($jsonHeader, true);
        $payload = json_decode($jsonPayload, true);

        if (is_null($header) || is_null($payload)) {
            return [null, null];
        }

        return [$header, $payload];
    }

    /**
     *
     * @param string $jwsString
     * @param JWK $jwk
     * @return bool
     */
    private function isJwsSignatureValid($jwsString, $jwk)
    {
        try {
            $loader = new Loader();
            $loader->loadAndVerifySignatureUsingKey($jwsString, $jwk, [self::JWK_ALG_ES256]);

            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     *
     * @param string $data
     * @return string
     */
    private function urlSafeBase64Encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     *
     * @param string $str
     * @return string
     */
    private function urlsafeBase64Hash($str)
    {
        return $this->urlSafeBase64Encode(hash(self::HASH_ALG_SHA256, $str, true));
    }

    /**
     *
     * @param string $arr
     * @return boolean
     */
    private function isSequentialArray($arr)
    {
        return is_array($arr) && ($arr === [] || array_keys($arr) === range(0, count($arr) - 1));
    }

    /**
     *
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    private function startsWith($haystack, $needle)
    {
        $length = strlen($needle);

        return (substr($haystack, 0, $length) === $needle);
    }
}
