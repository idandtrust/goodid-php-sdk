<?php

namespace GoodID\Helpers;

class GoodidSession implements \JsonSerializable
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
    public function __construct($id)
    {
        $this->id = $id;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @param $key
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
        // TODO: assert structure
        $session = new GoodidSession($data['id']);
        foreach ($data['data'] as $k => $v) {
            $session->set($k, $v);
        }
        return $session;
    }
}