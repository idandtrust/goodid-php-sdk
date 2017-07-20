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

namespace GoodID\Helpers\Logger;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;

/**
 * This can be used to send logs to the GoodID servers
 */
class RemoteLogger
{
    /**
     *
     * @var GoodIDServerConfig
     */
    private $goodIDServerConfig;

    /**
     *
     * @var string
     */
    private $accessToken;

    /**
     *
     * @var array
     */
    private $log;

    /**
     *
     * @param string $accessToken
     * @param GoodIDServerConfig $goodIDServerConfig configurations
     */
    public function __construct($accessToken, GoodIDServerConfig $goodIDServerConfig)
    {
        $this->goodIDServerConfig = $goodIDServerConfig;
        $this->accessToken = $accessToken;
        $this->log = [];
    }

    /**
     * Add log to internal log array
     *
     * @param string $claimName Claim name
     * @param string $errorDescription Error description
     * @param string $logLevel Log level
     * @throws GoodIDException on error
     */
    public function log($claimName, $errorDescription, $logLevel = Log::LEVEL_ERROR)
    {
        if (!is_string($claimName) || empty($claimName)) {
            throw new GoodIDException('$claimName must be a non-empty string');
        }

        if (!is_string($errorDescription) || empty($errorDescription)) {
            throw new GoodIDException('$errorDescription must be a non-empty string');
        }

        if (!Log::isValidLogLevel($logLevel)) {
            throw new GoodIDException('$logLevel is invalid');
        }

        array_push($this->log, [
            'log_level' => $logLevel,
            'claim_name' => $claimName,
            'error_description' => $errorDescription,
        ]);
    }

    /**
     * Send
     *
     * Sends logs to GoodID and clears the internal log array on success
     * It does nothing if no logs are present in the internal log array
     *
     * @throws GoodIDException on error
     */
    public function send()
    {
        if (empty($this->log)) {
            return;
        }

        $message = json_encode([
            'log_entries' => $this->log
        ]);

        $response = $this->callEndpoint(
            $this->goodIDServerConfig->getRemoteLoggingEndpointUri(),
            $this->accessToken,
            $message);

        if ($response->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
            throw new GoodIDException(
                'GoodID remote logging endpoint returned '
                . $response->getHttpStatusCode()
                . ", "
                . $response->getBody());
        }

        $this->log = [];
    }

    /**
     * Call Endpoint
     *
     * @codeCoverageIgnore
     *
     * @param string $endpointURI Endpoint URI
     * @param string $accessToken Access token
     * @param string $message Message
     * @return HttpResponse Response
     */
    protected function callEndpoint(
        $endpointURI,
        $accessToken,
        $message
    ) {
        $headers = [
            'Authorization' => 'Bearer ' . $accessToken
        ];

        $params = [
            'message' => $message
        ];

        return (new HttpRequest($endpointURI))
            ->setHeaders($headers)
            ->setParams($params)
            ->postFormUrlEncoded();
    }
}
