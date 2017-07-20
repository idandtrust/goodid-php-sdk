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
 * This class corresponds to an HTTP response
 * This is mainly constructed by the HttpRequest class
 */
class HttpResponse
{
    /**
     * Http status code for OK
     */
    const HTTP_STATUS_CODE_OK = 200;

    /**
     * Http status code for Unauthorized
     */
    const HTTP_STATUS_CODE_UNAUTHORIZED = 401;

    /**
     * @var int
     */
    private $httpStatusCode;

    /**
     * @var string
     */
    private $body;

    /**
     * @var array|null
     */
    private $headers;

    /**
     * HttpResponse constructor
     * Stores the HTTP status code and response body.
     * Parses and stores the HTTP header if given.
     *
     * @param int $httpStatusCode The response status code
     * @param string $body The response body
     * @param string|null $header The response header (all received data preceding the response body)
     */
    public function __construct($httpStatusCode, $body, $header = null)
    {
        $this->httpStatusCode = $httpStatusCode;
        $this->body = $body;
        $this->headers = is_null($header) ? null : $this->parseHeader($header);
    }

    /**
     * Returns the HTTP status code
     *
     * @return int HTTP status code
     */
    public function getHttpStatusCode()
    {
        return $this->httpStatusCode;
    }


    /**
     * Returns the response body
     *
     * @return string response body
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * A convenience function to get the response body JSON-decoded to an array.
     * Naturally this works only if the response body is a JSON string.
     *
     * @return array Decoded JSON
     *
     * @throws GoodIDException on error
     */
    public function getBodyJsonDecoded()
    {
        $result = json_decode($this->body, true);

        if (is_null($result)) {
            throw new GoodIDException('Json_decode returned null in HttpResponse::getBodyAsArray: ' . $this->body);
        }

        return $result;
    }

    /**
     * Returns the value of the desired header or null if nonexistent
     * HttpRequest::keepResponseHeaders must be called before making the request
     * to be able to get any headers with this method
     *
     * @param string $name Desired header name (case insensitive)
     *
     * @return string|null Header value (case unmodified), or null if nonexistent
     *
     * @throws GoodIDException if called on an object which does not have headers
     */
    public function getHeader($name)
    {
        if (is_null($this->headers)) {
            throw new GoodIDException('HttpResponse::getHeader called without HttpRequest::keepResponseHeaders');
        }
        $nameLower = strtolower($name);

        return isset($this->headers[$nameLower]) ? $this->headers[$nameLower] : null;
    }

    /**
     * Parse http headers to an associative array
     * For simplicity duplicate headers are not handled (the last one is kept)
     *
     * @param string $header The response header
     *
     * @return array headers
     */
    private function parseHeader($header)
    {
        $lines = explode("\r\n", $header);
        $lines[0] = ''; // First line is the HTTP query
        $array = [];
        foreach ($lines as $line) {
            $colonPos = strpos($line, ':');
            if ($colonPos === false) {
                continue;
            }
            $key = strtolower(trim(substr($line, 0, $colonPos)));
            $value = trim(substr($line, $colonPos + 1));
            $array[$key] = $value;
        }

        return $array;
    }
}
