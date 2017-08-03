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

/**
 * Incoming Request class
 */
class IncomingRequest
{
    /**
     * @var string
     */
    private $method;

    /**
     * @var array
     */
    private $params;

    /**
     * Constructor
     */
    public function __construct($stream = 'php://input')
    {
        $this->method = isset($_SERVER['REQUEST_METHOD'])
            ? $_SERVER['REQUEST_METHOD']
            : null;

        if ($this->method === 'GET') {
            $this->params = $_GET;
        } elseif ($this->method === 'POST') {
            $this->params = json_decode(file_get_contents($stream), true);
            if (is_null($this->params)) {
                throw new GoodIDException("Unsupported request format.");
            }
        } else {
            throw new GoodIDException("Unsupported request method.");
        }
    }

    /**
     * Get method
     *
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * Get trimmed string parameter
     *
     * @param string $name Parameter name
     *
     * @return string Value
     */
    public function getStringParameter($name)
    {
        if (isset($this->params[$name])) {
            return trim($this->params[$name]);
        }

        return '';
    }
}
