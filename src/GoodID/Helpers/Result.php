<?php

namespace GoodID\Helpers;

use GoodID\Exception\MissingClaimException;

class Result
{
    /**
     * @var array
     */
    private $claims;

    /**
     * @param array $claims
     */
    public function __construct(array $claims)
    {
        $this->claims = $claims;
    }

    /**
     * @param string $name
     *
     * @return mixed
     */
    public function get($name)
    {
        if (!isset($this->claims[$name])) {
            throw new MissingClaimException('Missing claim: ' . $name);
        }

        return $this->claims[$name];
    }
    
    /**
     * @param string $name
     *
     * @return bool
     */
    public function has($name)
    {
        return isset($this->claims[$name]);
    }

    /**
     * Convert to an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->claims;
    }

    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON()
    {
        return json_encode((object) $this->toArray(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Convert to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toJSON();
    }
}
