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

namespace GoodID\Helpers\Response;

use GoodID\Exception\GoodIDException;

/**
 * The class represents the received claims by the Authentication response
 */
class Claims
{
    /**
     * @var array
     */
    private $data;

    /**
     * Claims constructor
     *
     * @param array $data The claims array
     */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    /**
     * Returns the claims as a (possibly multilevel) array
     *
     * @return array Claims as an array
     */
    public function toArray()
    {
        return $this->data;
    }

    /**
     * Returns the claims encoded as a JSON string
     *
     * @return string Claims as a JSON string
     */
    public function toJson()
    {
        return json_encode((object)$this->data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Is there a (non-null) claim value with the given name?
     *
     * @param string $name Desired claim name
     *
     * @return bool has
     */
    public function has($name)
    {
        return isset($this->data[$name]);
    }

    /**
     * Get a claim value by claim name
     * Use the 'has' method to check for the existence of the claim
     * before calling the 'get' method.
     *
     * @param bool $name Claim name
     *
     * @return mixed Claim value
     *
     * @throws GoodIDException if the desired claim is not set
     */
    public function get($name)
    {
        if (!isset($this->data[$name])) {
            throw new GoodIDException("Claim $name not set.");
        }

        return $this->data[$name];
    }
}
