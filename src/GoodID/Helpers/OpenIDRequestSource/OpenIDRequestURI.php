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

use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\JwtUtil;
use GoodID\Helpers\Key\RSAPublicKey;

/**
 * Used to pass a request object by reference
 *
 * @link http://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter Request URI Parameter
 */
class OpenIDRequestURI implements OpenIDRequestSource
{
    /**
     * @var string
     */
    private $requestUri;

    /**
     * OpenIDRequestURI constructor
     *
     * @param string $requestUri Request URI
     */
    public function __construct($requestUri)
    {
        $this->requestUri = $requestUri;
    }

    /**
     * Returns the Request URI
     *
     * @return string Request URI
     */
    public function getRequestUri()
    {
        return $this->requestUri;
    }

    /**
     * Downloads the Request object from the Request URI
     * Validates and decodes it if it is not encrypted
     *
     * @param RSAPublicKey $sigPubKey The RP static key
     *
     * @return array|string Request object as an array, or self::CONTENT_IS_ENCRYPTED
     */
    public function download(RSAPublicKey $sigPubKey)
    {
        $jwt = $this->retrieveUriContents($this->requestUri);

        if (JwtUtil::isCompactJwe($jwt)) {
            return self::CONTENT_IS_ENCRYPTED;
        }

        return $sigPubKey->verifyCompactJws($jwt);
    }

    /**
     * Returns the claims as an array if they are not encrypted
     *
     * @param RSAPublicKey $sigPubKey RP static signing key
     *
     * @return array|string Claims array or OpenIDRequestSource::CONTENT_IS_ENCRYPTED
     */
    public function getClaims(RSAPublicKey $sigPubKey)
    {
        $res = $this->download($sigPubKey);
        if ($res === self::CONTENT_IS_ENCRYPTED) {
            return $res;
        }

        return isset($res['claims']) ? $res['claims'] : [];
    }

    /**
     * @codeCoverageIgnore
     *
     * @param string $requestUri
     *
     * @return string
     */
    protected function retrieveUriContents($requestUri)
    {
        return (new HttpRequest($requestUri))->get()->getBody();
    }
}
