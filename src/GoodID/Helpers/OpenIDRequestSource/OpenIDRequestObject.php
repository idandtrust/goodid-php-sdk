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

namespace GoodID\Helpers\OpenIDRequestSource;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;

/**
 * Used to pass a request object by value
 *
 * @link http://openid.net/specs/openid-connect-core-1_0.html#RequestObject Request Object
 */
class OpenIDRequestObject implements OpenIDRequestSource
{
    /**
     * @var array
     */
    private $claims;

    /**
     * @var array
     */
    private $scopes = array();

    /**
     * OpenIDRequestObject constructor
     *
     * @param string|array $claims The requested claims as a string (JSON) or array.
     *
     * @throws GoodIDException
     */
    public function __construct($claims)
    {
        if (is_string($claims)) {
            $this->claims = json_decode($claims, true);

            if (is_null($this->claims)) {
                throw new GoodIDException("Can not decode claims JSON.");
            }
        } elseif (is_array($claims)) {
            $this->claims = $claims;
        } else {
            throw new GoodIDException("Claims parameter must be string (JSON) or array.");
        }
        
        $this->scopes[] = self::SCOPE_OPENID;
    }

    /**
     * @param string $scope
     */
    public function addScope($scope)
    {
        if (!in_array($scope, $this->scopes)) {
            $this->scopes[] = $scope;
        }
    }

    /**
     * Generates request object JWT string which can be used for example as a request URI's content
     *
     * @param RSAPrivateKey $sigKey RP signing key-pair, used to sign the generated request object
     * @param string $clientId RP client id
     * @param string $redirectUri Redirect URI
     * @param GoodIDServerConfig $goodIdServerConfig Configurations
     * @param int|null $maxAge Maximum authentication age
     *
     * @return string JWT
     *
     * @throws GoodIDException
     */
    public function generateJwt(
        RSAPrivateKey $sigKey,
        $clientId,
        $redirectUri,
        GoodIDServerConfig $goodIdServerConfig,
        $maxAge = null
    ) {
        $array = $this->toArray(
            $clientId,
            $redirectUri,
            $goodIdServerConfig,
            $maxAge
        );

        return $this->generateFromArray($array, $sigKey);
    }

    /**
     * To array
     *
     * @param string $clientId RP client id
     * @param string $redirectUri Redirect URI
     * @param GoodIDServerConfig $goodIdServerConfig Configurations
     * @param int|null $maxAge Maximum authentication age
     * @param string|null $appResponseUri
     *
     * @return array
     */
    public function toArray(
        $clientId,
        $redirectUri,
        GoodIDServerConfig $goodIdServerConfig,
        $maxAge = null,
        $appResponseUri = null
    ) {
        $array = [
            'iss' => $clientId,
            'aud' => $goodIdServerConfig->getAudienceUri(),
            'response_type' => self::RESPONSE_TYPE_CODE,
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => implode(' ', $this->scopes),
            'claims' => count($this->claims) === 0 ? [] : $this->emptyArrayToObjectRecursive($this->claims)
        ];

        if (!is_null($maxAge)) {
            if ($maxAge < 0) {
                throw new \InvalidArgumentException('max_age can not be negative');
            }
            $array['max_age'] = $maxAge;
        }

        if (!is_null($appResponseUri)) {
            $array['app_response_uri'] = $appResponseUri;
        }

        return $array;
    }

    /**
     * Generate from array
     *
     * @param array $array Request Object as array
     * @param RSAPrivateKey $sigPrivKey Private signature key
     *
     * @return string Request Object as JWT string
     */
    public function generateFromArray(array $array, RSAPrivateKey $sigPrivKey)
    {
        return $sigPrivKey->signAsCompactJws($array);
    }

    /**
     * Converts all empty arrays to empty (stdClass) objects recursively
     *
     * @param mixed $dataStructure Data structure
     *
     * @return mixed Data structure
     */
    private function emptyArrayToObjectRecursive($dataStructure)
    {
        if (is_array($dataStructure)) {
            if (empty($dataStructure)) {
                return new \stdClass();
            }

            $newArray = [];

            foreach ($dataStructure as $key => $value) {
                $newArray[$key] = $this->emptyArrayToObjectRecursive($value);
            }

            return $newArray;
        } elseif (is_object($dataStructure) && $dataStructure instanceof \stdClass) {
            $newObject = new \stdClass();

            foreach ($dataStructure as $key => $value) {
                $newObject->$key = $this->emptyArrayToObjectRecursive($value);
            }

            return $newObject;
        } else {
            return $dataStructure;
        }
    }

    /**
     * Returns the claims as an array
     *
     * @param RSAPublicKey $sigKey RP Signature key
     *
     * @return array Claims as an array
     */
    public function getClaims(RSAPublicKey $sigKey)
    {
        return $this->claims;
    }

    /**
     * Returns the scopes as an array
     *
     * @param RSAPublicKey $sigKey RP Signature key
     *
     * @return array scopes as an array
     */
    public function getScopes(RSAPublicKey $sigKey)
    {
        return $this->scopes;
    }
}
