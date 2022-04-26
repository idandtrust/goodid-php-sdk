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

namespace GoodID\Helpers;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;
use Jose\Component\Core\JWKSet;

/**
 * This class provides the URI's of the GoodID endpoints
 */
class GoodIDServerConfig
{
    /**
     * @var JWKSet|null
     */
    private $keystore;

    /**
     * @return string GoodID Issuer URI
     */
    public function getIssuerUri()
    {
        return "https://idp.goodid.net";
    }

    /**
     * @return string GoodID Identity Provider URI
     */
    public function getIdpUri()
    {
        return 'https://idp.goodid.net';
    }

    /**
     * @return string GoodID Audience URI
     */
    public function getAudienceUri()
    {
        return $this->getIssuerUri();
    }

    /**
     * @return string GoodID Pass URI
     */
    public function getPassUri()
    {
        return 'https://pass.goodid.net';
    }

    /**
     * @return string GoodID Push URI
     */
    public function getPushUri()
    {
        return 'https://push.goodid.net';
    }

    /**
     * @return string GoodID Authorization Endpoint URI
     */
    public function getAuthorizationEndpointUri()
    {
        return $this->getIdpUri() . '/oidc/authorize';
    }

    /**
     * @return string GoodID Fast Authorization Endpoint URI
     */
    public function getFastAuthorizationEndpointUri()
    {
        return $this->getIdpUri() . '/fast/authorize';
    }

    /**
     * @return string GoodID Token Endpoint URI
     */
    public function getTokenEndpointUri()
    {
        return $this->getIdpUri() . '/oidc/token';
    }

    /**
     * @return string GoodID Userinfo Endpoint URI
     */
    public function getUserinfoEndpointUri()
    {
        return $this->getIdpUri() . '/oidc/userinfo';
    }

    /**
     * @return string GoodID Remote Logging Endpoint URI
     */
    public function getRemoteLoggingEndpointUri()
    {
        return $this->getIdpUri() . '/oidc/client-log-sink';
    }

    /**
     * @return string GoodID JWKS URI
     */
    public function getJwksUri()
    {
        return $this->getIdpUri() . '/jwks.json';
    }

    /**
     * @return string
     */
    public function getPushSenderUri()
    {
        return $this->getPushUri() . '/push-messages';
    }

    /**
     * @return JWKSet
     *
     * @throws ValidationException
     */
    public function getKeystore()
    {
        if (!isset($this->keystore)) {
            $response = (new HttpRequest($this->getJwksUri()))->get();

            if ($response->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
                throw new ValidationException('GoodID jwksuri unreachable');
            }

            try {
                $this->keystore = JWKSet::createFromJson($response->getBody());
            } catch (\Exception $e) {
                throw new ValidationException('GoodID jwksuri content is not valid JSON');
            }
        }

        return $this->keystore;
    }
}
