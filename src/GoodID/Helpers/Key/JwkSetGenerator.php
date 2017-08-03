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

namespace GoodID\Helpers\Key;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;
use GoodID\Helpers\Key\RSAPublicKey;

/**
 * JwkSetGenerator class
 */
class JwkSetGenerator
{
    /**
     * Generate JWKS URI content
     *
     * @param RSAPublicKey $sigKey Service provider signing key
     * @param RSAPublicKey $encKey Service provider encryption key
     * @param string|null $existingJwksUri The existing JWKS URI of the Service Provider.
     *     If $existingJwksUri is set, the returned content will include the keys from the existing JWKS URI too.
     * @return string JWKS-URI content (JWK Set in JSON format)
     */
    public function generateJwksUriContent(RSAPublicKey $sigKey, RSAPublicKey $encKey, $existingJwksUri = null)
    {
        if (!is_null($existingJwksUri)) {
            $httpResponse = $this->callEndpoint($existingJwksUri);
            if ($httpResponse->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
                throw new GoodIDException(
                    'Existing JWKS URI returned '
                    . $httpResponse->getHttpStatusCode()
                    . ", "
                    . $httpResponse->getBody());
            }

            $responseBody = $httpResponse->getBody();

            $jwkSet = json_decode($responseBody, true);

            if (!$jwkSet || !is_array($jwkSet) || !array_key_exists('keys', $jwkSet) || !is_array($jwkSet['keys'])) {
                throw new GoodIDException('Format of existing JWKS URI content is invalid');
            }
        } else {
            $jwkSet = [
                'keys' => []
            ];
        }

        $existingKids = [
            'enc' => [],
            'sig' => [],
        ];

        foreach ($jwkSet['keys'] as $key) {
            if (!isset($key['kid']) || !isset($key['use']) || !in_array($key['use'], ['enc', 'sig'])) {
                throw new GoodIDException('Format of existing JWKS URI content is invalid');
            }

            if (isset($existingKids[$key['use']][$key['kid']])) {
                throw new GoodIDException('Duplicate use-kid pair in existing JWKS URI content');
            }

            $existingKids[$key['use']][$key['kid']] = true;
        }

        $sigJwk = $sigKey->getPublicKeyAsJwkArray();
        $sigJwk['use'] = 'sig';
        $sigJwk['kid'] = $sigKey->getKid();

        if (isset($existingKids[$sigJwk['use']][$sigJwk['kid']])) {
            throw new GoodIDException('Result would contain a duplicate use-kid pair');
        }

        array_push($jwkSet['keys'], $sigJwk);

        $encJwk = $encKey->getPublicKeyAsJwkArray();
        $encJwk['use'] = 'enc';
        $encJwk['kid']  = $encKey->getKid();

        if (isset($existingKids[$encJwk['use']][$encJwk['kid']])) {
            throw new GoodIDException('Result would contain a duplicate use-kid pair');
        }

        array_push($jwkSet['keys'], $encJwk);

        return json_encode($jwkSet);
    }

    /**
     * Call Endpoint
     *
     * @codeCoverageIgnore
     *
     * @param string $endpointURI Endpoint URI
     * @return HttpResponse Response
     */
    protected function callEndpoint($endpointURI)
    {
        return (new HttpRequest($endpointURI))->get();
    }
}
