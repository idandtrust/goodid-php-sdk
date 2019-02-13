<?php

namespace GoodID\Helpers;

class NormalizedJsonTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itNormalizesAndEncodesComplexObjects()
    {
        $object = (object)[
            'c' => 3,
            'b' => [
                'arr' => [
                    'b' => 2,
                    'a' => 1,
                    'c' => 3,
                ],
                'obj' => (object) [
                    'a' => 1,
                    'c' => 3,
                    'b' => 2,
                ],
                'emptyArray' => [],
                'nullObject' => (object) [],
                'array' => [
                    2,
                    1,
                    3
                ]
            ],
            'a' => 1,
        ];

        $normalized = '{"a":1,"b":{"arr":{"a":1,"b":2,"c":3},"array":[2,1,3],"emptyArray":[],"nullObject":{},"obj":{"a":1,"b":2,"c":3}},"c":3}';
        $this->assertEquals($normalized, NormalizedJson::encode($object));
    }

    /**
     * @test
     */
    public function itHashesComplexObjects()
    {
        $object = (object)[
            'c' => 3,
            'b' => [
                'arr' => [
                    'b' => 2,
                    'a' => 1,
                    'c' => 3,
                ],
                'obj' => (object) [
                    'a' => 1,
                    'c' => 3,
                    'b' => 2,
                ],
                'emptyArray' => [],
                'nullObject' => (object) [],
                'array' => [
                    2,
                    1,
                    3
                ]
            ],
            'a' => 1,
        ];

        $hash = 'AS57OoDHWR63YJe03NYY-7_70UhuRa7i7BywvVY5qYc';
        $this->assertEquals($hash, NormalizedJson::hash($object));
    }
}