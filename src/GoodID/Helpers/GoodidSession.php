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
     * @var int
     */
    private $iat;

    /**
     * @var int 
     */
    private $ttl;

    /**
     * @var array
     */
    private $data = [];

    /**
     * @param int $ttl
     */
    public function __construct($ttl = null)
    {
        $this->id = Base64Url::encode(random_bytes(32), false);
        $this->iat = time();
        $this->ttl = !is_null($ttl) ? $ttl : 1200;
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
     * @param int $ttl
     */
    private function setTtl($ttl)
    {
        $this->ttl = (int)$ttl;
    }

    /**
     * @param int $iat
     */
    private function setIat($iat)
    {
        $this->iat = (int)$iat;
    }

    /**
     * @return \DateTime
     */
    public function getIat()
    {
        return \DateTime::createFromFormat('U', $this->iat);
    }

    /**
     * @return \DateTime
     */
    public function getTtl()
    {
        return \DateTime::createFromFormat('U', $this->iat + $this->ttl);
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
     * @param string $key
     */
    public function remove($key)
    {
        unset($this->data[$key]);
    }

    /**
     * @return array
     */
    public function jsonSerialize()
    {
        return [
            'id' => $this->id,
            'iat' => $this->iat,
            'ttl' => $this->ttl,
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
        if (count($data) !== 4
            || !array_key_exists('id', $data)
            || !array_key_exists('data', $data)
            || !array_key_exists('iat', $data)
            || !array_key_exists('ttl', $data)) {
            throw new \InvalidArgumentException('Malformed serialized goodid session');
        }
        if (!is_string($data['id']) || !is_array($data['data'])) {
            throw new \InvalidArgumentException('Malformed serialized goodid session');
        }

        $session = new GoodidSession();
        $session->setId($data['id']);
        $session->setIat($data['iat']);
        $session->setTtl($data['ttl']);
        foreach ($data['data'] as $k => $v) {
            $session->set($k, $v);
        }
        return $session;
    }
}