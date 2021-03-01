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
use GoodID\Helpers\Key\RSAPublicKey;
/**
 * JwkSetGenerator class
 */
class JwkSetGenerator
{
    private $keys = [];

    /**
     * @param KeyInterface $key
     */
    public function addKey(KeyInterface $key)
    {
        $this->keys[] = $key;
    }

    /**
     * @return string
     * 
     * @throws GoodIDException
     * @throws \Exception
     */
    public function generate()
    {
        $jwks = [
            'keys' => []
        ];

        $existingKids = [
            'sig' => [],
            'enc' => []
        ];

        $requestSigKey = null;
        $requestEncKey = null;

        foreach ($this->keys as $key) {
            $keyArray = $key->getPublicKeyAsJwkArray();
            if (isset($existingKids[$keyArray['use']][$keyArray['kid']])) {
                throw new GoodIDException('Duplicate use-kid pair!');
            }

            $existingKids[$keyArray['use']][$keyArray['kid']] = true;
            array_push($jwks['keys'], $keyArray);

            if ($key instanceof RSAPublicKey && $keyArray['use'] == 'sig') {
                $requestSigKey = $key;
            } else if ($key instanceof RSAPublicKey && $keyArray['use'] == 'enc') {
                $requestEncKey = $key;
            }
        }

        if (is_null($requestEncKey) || is_null($requestSigKey)) {
            throw new GoodIDException('Missing required keys.');
        }

        return json_encode($jwks);
    }

    public function run()
    {
        $jwksContent = $this->generate();
        header("Content-type:application/jwk-set+json");
        echo $jwksContent;
        exit;
    }
}