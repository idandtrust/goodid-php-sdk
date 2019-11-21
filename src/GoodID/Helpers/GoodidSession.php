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

use Base64Url\Base64Url;

final class GoodidSession implements \JsonSerializable
{
    /**
     * @var string
     */
    private $id;

    /**
     * @var array
     */
    private $data = [];

    /**
     * @param string $id
     */
    public function __construct()
    {
        $this->id = Base64Url::encode(random_bytes(32), false);
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param string $id
     */
    private function setId($id)
    {
        $this->id = $id;
    }

    /**
     * @param $key
     *
     * @return mixed|null
     */
    public function get($key)
    {
        return array_key_exists($key, $this->data) ? $this->data[$key] : null;
    }

    /**
     * @param string $key
     * @param mixed $value
     */
    public function set($key, $value)
    {
        $this->data[$key] = $value;
    }

    /**
     * @return array
     */
    public function jsonSerialize()
    {
        return [
            'id' => $this->id,
            'data' => $this->data,
        ];
    }

    /**
     * @param string $string
     *
     * @return GoodidSession
     */
    public static function createFromJson($string)
    {
        $data = json_decode($string, true);
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Malformed serialized goodid session');
        }
        if (count($data) !== 2 || !array_key_exists('id', $data) || !array_key_exists('data', $data)) {
            throw new \InvalidArgumentException('Malformed serialized goodid session');
        }
        if (!is_string($data['id']) || !is_array($data['data'])) {
            throw new \InvalidArgumentException('Malformed serialized goodid session');
        }

        $session = new GoodidSession();
        $session->setId($data['id']);
        foreach ($data['data'] as $k => $v) {
            $session->set($k, $v);
        }
        return $session;
    }
}