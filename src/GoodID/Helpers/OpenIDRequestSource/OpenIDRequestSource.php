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

use GoodID\Helpers\Key\RSAPublicKey;

/**
 * Used to pass a request object either by value (OpenIDRequestObject,
 * OpenIDRequestObjectJWT) or by reference (OpenIDRequestURI)
 */
interface OpenIDRequestSource
{
    /**
     * This return value indicates that the request URI content is encrypted
     * by the GoodID Server's public key, so it can not be decrypted by the
     * GoodID PHP SDK.
     */
    const CONTENT_IS_ENCRYPTED = "content-is-encrypted";

    /**
     * The response type for authorization code flow must be 'code'
     */
    const RESPONSE_TYPE_CODE = 'code';

    /**
     * The scope must include 'openid'
     */
    const SCOPE_OPENID = 'openid';

    /**
     * Returns the claims corresponding to the OpenIDRequestSource if they are
     * not encrypted, otherwise it returns OpenIDRequestSource::CONTENT_IS_ENCRYPTED
     * Signature check is performed if the OpenIDRequestSource contains a
     * pre-generated JWS
     *
     * @param RSAPublicKey $sigPubKey RP static signing key
     *
     * @return array|string Claims array or OpenIDRequestSource::CONTENT_IS_ENCRYPTED
     */
    public function getClaims(RSAPublicKey $sigPubKey);
}
