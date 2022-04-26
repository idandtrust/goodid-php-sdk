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

namespace GoodID\Authentication\Endpoint;

use GoodID\Exception\GoodIDException;

/**
 * This class is responsible to build the Authentication Request
 *
 * @link http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest Authentication Request
 */
class InitiateLoginUriBuilder extends AbstractInitiateLoginUriBuilder
{
    /**
     * Builds the authentication request URI used at normal sign-ins
     *
     * @return string
     *
     * @throws GoodIDException
     */
    public function buildRequestUrl()
    {
        $this->sessionDataHandler->removeAll();
        $queryParams = $this->buildQueryParams();
        $this->setSessionData();
        $this->saveGoodIDSession();

        return $this->goodIdServerConfig->getAuthorizationEndpointUri() . '?' . http_build_query($queryParams);
    }

    /**
     * @return array
     */
    public function getClaims()
    {
        return $this->requestSource->getClaims($this->signingKey);
    }

    /**
     * The main logic of this endpoint
     *
     * @codeCoverageIgnore
     */
    public function run()
    {
        header('Location: ' . $this->buildRequestUrl());
    }
}
