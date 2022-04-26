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

namespace GoodID\Helpers\Http;

use GoodID\Exception\GoodIDException;

/**
 * Instances of this class can build and execute an HTTP request
 * This class can be conveniently used with parameter chaining
 */
class HttpRequest
{
    /**
     * @var array
     */
    private $queryParams = [];

    /**
     * @var array
     */
    private $curlOpts;

    /**
     * @var resource
     */
    private static $ch;

    /**
     * HttpRequest constructor
     *
     * @param string $uri The target URI
     */
    public function __construct($uri)
    {
        $this->curlOpts = [
            CURLOPT_URL => $uri,
            CURLOPT_RETURNTRANSFER => true
        ];
    }

    /**
     * Sets the query (or POST) parameters
     *
     * @param array $queryParams Query parameters
     *
     * @return $this
     */
    public function setParams(array $queryParams)
    {
        $this->queryParams = $queryParams;

        return $this;
    }

    /**
     * Sets the HTTP request headers
     *
     * @param array $headers
     *
     * @return $this
     */
    public function setHeaders(array $headers)
    {
        $headersCurl = [];
        foreach ($headers as $key => $value) {
            $headersCurl[] = $key . ': ' . $value;
        }
        $this->curlOpts[CURLOPT_HTTPHEADER] = $headersCurl;

        return $this;
    }

    /**
     * Sets whether the HTTP response headers have to be saved in the HttpResponse
     *
     * @param bool $keepResponseHeaders Keep response headers
     *
     * @return $this
     */
    public function setKeepResponseHeaders($keepResponseHeaders = true)
    {
        $this->curlOpts[CURLOPT_HEADER] = (bool)$keepResponseHeaders;

        return $this;
    }

    /**
     * Sends the request with the GET method
     *
     * @return HttpResponse The response
     */
    public function get()
    {
        if ($this->queryParams) {
            $this->curlOpts[CURLOPT_URL] .= '?' . http_build_query($this->queryParams);
        }

        return $this->curl($this->curlOpts);
    }

    /**
     * Sends the request with the POST method using application/x-www-form-urlencoded parameter encoding
     *
     * @return HttpResponse The response
     */
    public function postFormUrlEncoded()
    {
        $this->curlOpts[CURLOPT_POST] = true;
        $this->curlOpts[CURLOPT_POSTFIELDS] = http_build_query($this->queryParams);

        return $this->curl($this->curlOpts);
    }

    /**
     * @param mixed $data
     * @return HttpResponse
     */
    public function postJson($data)
    {
        return $this->post(json_encode($data), 'application/json');
    }

    /**
     * @param mixed $data
     * @param string $contentyType
     * 
     * @return HttpResponse
     */
    public function post($data, $contentyType)
    {
        $assocHeaders = [];
        $curlHeaders = array_key_exists(CURLOPT_HTTPHEADER, $this->curlOpts) ? $this->curlOpts[CURLOPT_HTTPHEADER] : [];
        foreach ($curlHeaders as $curlHeader) {
            $assocHeader = explode(': ', $curlHeader, 2);
            $assocHeaders[$assocHeader[0]] = $assocHeader[1];
        }
        $assocHeaders = array_merge([
                'Content-Type' => $contentyType,
                'Content-Length' => strlen($data),
            ],
            $assocHeaders
        );

        $this->setHeaders($assocHeaders);
        $this->curlOpts[CURLOPT_POST] = true;
        $this->curlOpts[CURLOPT_POSTFIELDS] = $data;

        return $this->curl($this->curlOpts);
    }

    /**
     * 
     * @param string $text
     * 
     * @return HttpResponse response
     */
    public function postText($text)
    {
        $assocHeaders = [];
        $curlHeaders = array_key_exists(CURLOPT_HTTPHEADER, $this->curlOpts) ? $this->curlOpts[CURLOPT_HTTPHEADER] : [];
        foreach ($curlHeaders as $curlHeader) {
            $assocHeader = explode(': ', $curlHeader, 2);
            $assocHeaders[$assocHeader[0]] = $assocHeader[1];
        }
        $assocHeaders = array_merge([
                'Content-Type' => 'text/plain',
                'Content-Length' => strlen($text),
            ],
            $assocHeaders
        );

        $this->setHeaders($assocHeaders);
        $this->curlOpts[CURLOPT_POST] = true;
        $this->curlOpts[CURLOPT_POSTFIELDS] = $text;

        return $this->curl($this->curlOpts);
    }

    public function putJson($data)
    {
        $jsonData = json_encode($data);

        $assocHeaders = [];
        $curlHeaders = array_key_exists(CURLOPT_HTTPHEADER, $this->curlOpts) ? $this->curlOpts[CURLOPT_HTTPHEADER] : [];
        foreach ($curlHeaders as $curlHeader) {
            $assocHeader = explode(': ', $curlHeader, 2);
            $assocHeaders[$assocHeader[0]] = $assocHeader[1];
        }
        $assocHeaders = array_merge([
            'Content-Type' => 'application/json',
            'Content-Length' => strlen($jsonData),
        ],
            $assocHeaders
        );

        $this->setHeaders($assocHeaders);
        $this->curlOpts[CURLOPT_CUSTOMREQUEST] = 'PUT';
        $this->curlOpts[CURLOPT_POSTFIELDS] = $jsonData;

        return $this->curl($this->curlOpts);
    }

    public function delete()
    {
        $this->curlOpts[CURLOPT_CUSTOMREQUEST] = 'DELETE';

        return $this->curl($this->curlOpts);
    }

    /**
     * Calls curl with the given parameters and returns the response as a HttpResponse
     *
     * @param array $curlOpts Curl options
     *
     * @return HttpResponse response
     *
     * @throws GoodIDException on error
     */
    private function curl(array $curlOpts)
    {
        try {
            $ch = $this->getConnection();

            $result = curl_setopt_array($ch, $curlOpts);
            if ($result === false) {
                throw new GoodIDException("curl_setopt_array failed");
            }
            $result = curl_exec($ch);
            if ($result === false) {
                throw new GoodIDException("curl_exec failed");
            }
            $httpStatusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            if ($httpStatusCode === false) {
                throw new GoodIDException("curl_getinfo did not return http status code");
            }
            if (isset($curlOpts[CURLOPT_HEADER]) && $curlOpts[CURLOPT_HEADER]) {
                $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
                if ($headerSize === false) {
                    throw new GoodIDException("curl_getinfo did not return header size");
                }
                $header = substr($result, 0, $headerSize);
                $body = substr($result, $headerSize);

                return new HttpResponse($httpStatusCode, $body, $header);
            } else {
                return new HttpResponse($httpStatusCode, $result);
            }
        } catch (GoodIDException $ex) {
            $this->closeConnection();
            throw $ex;
        }
    }

    /**
     * @return resource
     *
     * @throws GoodIDException
     */
    private function getConnection()
    {
        if (!isset(self::$ch)) {
            $ch = curl_init();
            if ($ch === false) {
                throw new GoodIDException("curl_init failed");
            }
            self::$ch = $ch;
        } else {
            curl_reset(self::$ch);
        }
        return self::$ch;
    }

    private function closeConnection()
    {
        if (isset(self::$ch)) {
            curl_close(self::$ch);
            self::$ch = null;
        }
    }
}
