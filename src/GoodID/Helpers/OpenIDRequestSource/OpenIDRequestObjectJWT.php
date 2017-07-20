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
use GoodID\Helpers\JwtUtil;
use GoodID\Helpers\Key\RSAPublicKey;

/**
 * Used to pass a pre-generated request object by value
 */
class OpenIDRequestObjectJWT implements OpenIDRequestSource
{
    /**
     * @var string
     */
    private $jwt;

    /**
     * OpenIDRequestObjectJWT constructor
     *
     * @param string $jwt JWT
     */
    public function __construct($jwt)
    {
        $this->jwt = $jwt;
    }

    /**
     * Get JWT
     *
     * @return string JWT
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * Returns the claims as an array if they are not encrypted
     *
     * @param RSAPublicKey $sigPubKey The RP signature key (public)
     *
     * @return array|string Claims or self::CONTENT_IS_ENCRYPTED
     *
     * @throws GoodIDException on error
     */
    public function getClaims(RSAPublicKey $sigPubKey)
    {
        if (JwtUtil::isCompactJwe($this->jwt)) {
            return self::CONTENT_IS_ENCRYPTED;
        } elseif (JwtUtil::isCompactJws($this->jwt)) {
            $tokenArray = $sigPubKey->verifyCompactJws($this->jwt);

            return isset($tokenArray['claims']) ? $tokenArray['claims'] : [];
        } else {
            throw new GoodIDException("Unsupported JWT format.");
        }
    }
}
