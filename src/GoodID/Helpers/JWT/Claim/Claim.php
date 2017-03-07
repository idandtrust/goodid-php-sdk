<?php

namespace GoodID\Helpers\JWT\Claim;

use GoodID\Helpers\JWT\Claim\RegisteredClaim;
use JWX\JWT\Claim\Claim as ParentClaim;

class Claim extends ParentClaim
{
    /**
     * Initialize from a name and a value.
     *
     * Returns a specific claim object if applicable.
     *
     * @param string $name Claim name
     * @param mixed $value Claim value
     *
     * @return Claim
     */
    public static function fromNameAndValue($name, $value)
    {
        if (array_key_exists($name, RegisteredClaim::MAP_NAME_TO_CLASS)) {
            $cls = RegisteredClaim::MAP_NAME_TO_CLASS[$name];

            return $cls::fromJSONValue($value);
        }

        return new self($name, $value);
    }

    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON()
    {
        return json_encode((array)$this->value(), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_NUMERIC_CHECK);
    }
}
