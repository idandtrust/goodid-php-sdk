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

namespace GoodID\Helpers\Request;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;

/**
 * Objects of this class can make a request to the GoodID Server's Userinfo Endpoint
 */
class UserinfoRequest
{
    /**
     * @var string
     */
    private $userInfoJwe;

    /**
     * @var string
     */
    private $accessToken;

    /**
     * @var GoodIDServerConfig
     */
    private $goodIdServerConfig;

    /**
     * Make a request to the GoodID Server's Userinfo Endpoint
     *
     * @link http://openid.net/specs/openid-connect-core-1_0.html#UserInfo UserInfo
     *
     * @param string $accessToken Access Token
     * @param GoodIDServerConfig $goodIdServerConfig Internal parameter
     */
    public function __construct($accessToken, $goodIdServerConfig)
    {
        $this->accessToken = $accessToken;
        $this->goodIdServerConfig = $goodIdServerConfig;
    }

    /**
     * @throws GoodIDException
     */
    public function execute()
    {
        $userInfoResponse = $this->callEndpoint(
            $this->goodIdServerConfig->getUserinfoEndpointUri(),
            $this->accessToken
        );

        $wwwAuthenticateHeader = $userInfoResponse->getHeader('WWW-Authenticate');
        if (!is_null($wwwAuthenticateHeader) && stripos($wwwAuthenticateHeader, "error") !== false) {
            throw new GoodIDException('Authentication failed to userinfo endpoint: ' . $wwwAuthenticateHeader);
        }

        if ($userInfoResponse->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
            throw new GoodIDException('Userinfo endpoint http status code: ' . $userInfoResponse->getHttpStatusCode());
        }

        $this->userInfoJwe = $userInfoResponse->getBody();
    }

    /**
     * Gets the returned Userinfo as a compact JWE
     *
     * @return string
     */
    public function getUserInfoJwe()
    {
        return $this->userInfoJwe;
    }

    /**
     * @codeCoverageIgnore
     *
     * @param string $endpointURI
     * @param string $accessToken
     *
     * @return HttpResponse
     */
    protected function callEndpoint($endpointURI, $accessToken)
    {
        return (new HttpRequest($endpointURI))
            ->setKeepResponseHeaders()
            ->setHeaders([
                'Authorization' => 'Bearer ' . $accessToken
            ])->get();
    }
}
