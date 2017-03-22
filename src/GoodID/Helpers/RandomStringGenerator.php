<?php

namespace GoodID\Helpers;

use GoodID\Exception\GoodIDException;

/**
 * Class RandomStringGenerator
 */
class RandomStringGenerator
{
    /**
     * Generate a random string, using a cryptographically secure
     * pseudorandom number generator (random_int)
     *
     * For PHP 7, random_int is a PHP core function
     * For PHP 5.x, depends on https://github.com/paragonie/random_compat
     *
     * @param int $length      How many characters do we want?
     * @param string $keyspace A string of all possible characters
     *                         to select from
     * @return string
     */
    public static function getPseudoRandomString($length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
    {
        try {
            $str = '';
            $max = mb_strlen($keyspace, '8bit') - 1;

            for ($i = 0; $i < $length; ++$i) {
                $str .= $keyspace[random_int(0, $max)];
            }
        } catch (\Exception $e) {
            throw new GoodIDException('Please make sure you enable mcrypt or /dev/urandom is readable!');
        }

        return $str;
    }
}
