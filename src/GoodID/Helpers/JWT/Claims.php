<?php

namespace GoodID\Helpers\JWT;

use GoodID\Helpers\JWT\Claim\Claim;
use JWX\JWT\Claims as ParentClaims;

class Claims extends ParentClaims
{
    /**
     * Initialize from a JSON string.
     *
     * @param string $json JSON
     *
     * @throws \UnexpectedValueException If JSON is malformed
     *
     * @return self
     */
    public static function fromJSON($json)
    {
        $claims = array();
        $fields = json_decode($json, true, 32, JSON_BIGINT_AS_STRING);

        if (!is_array($fields)) {
            throw new \UnexpectedValueException("Invalid JSON.");
        }

        foreach ($fields as $name => $value) {
            $claims[] = Claim::fromNameAndValue($name, $value);
        }

        return new self(...$claims);
    }
    
    /**
     * Convert to a JSON.
     *
     * @return string
     */
    public function toJSON()
    {
        $data = array();
        foreach ($this->_claims as $claim) {
            $data[$claim->name()] = $claim->value();
        }

        return json_encode((object) $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Convert to an array.
     *
     * @return array
     */
    public function toArray()
    {
        $data = array();
        foreach ($this->_claims as $claim) {
            $data[$claim->name()] = $claim->value();
        }

        return $data;
    }
}
