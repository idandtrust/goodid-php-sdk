<?php

namespace GoodID\Helpers\Response;

class ClaimsTest extends \PHPUnit_Framework_TestCase
{
    private $data = [
        'id_token' => [
            'sub_jwk' => [
                'essential' => true,
            ],
            'middle_name' => [
                'essential' => true,
            ],
        ],
        'userinfo' => [
            'given_name' => [
                'essential' => true,
            ],
            'family_name' => [
                'essential' => true,
            ],
        ],
    ];
    private $json = '{"id_token":{"sub_jwk":{"essential":true},"middle_name":{"essential":true}},"userinfo":{"given_name":{"essential":true},"family_name":{"essential":true}}}';

    /**
     * @test
     */
    public function itCanBeCreated()
    {
        $claims = new Claims([]);

        $this->assertInstanceOf(Claims::class, $claims);
    }

    /**
     * @test
     */
    public function itCanBeTurnedIntoAnArray()
    {
        $claims = new Claims($this->data);

        $this->assertEquals($this->data, $claims->toArray());
    }

    /**
     * @test
     */
    public function itCanBeTurnedIntoJson()
    {
        $claims = new Claims($this->data);

        $this->assertJsonStringEqualsJsonString($this->json, $claims->toJson());
    }

    /**
     * @test
     */
    public function itReturnsContainedClaims()
    {
        $claims = new Claims($this->data);

        $userInfo = [
            'given_name' => [
                'essential' => true,
            ],
            'family_name' => [
                'essential' => true,
            ],
        ];
        $this->assertEquals($userInfo, $claims->get('userinfo'));
    }

    /**
     * @test
     */
    public function itReportsClaimsIncluded()
    {
        $claims = new Claims($this->data);

        $this->assertTrue($claims->has('userinfo'));
        $this->assertFalse($claims->has('not-included'));
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Claim not-included not set.
     */
    public function itFailsWhileAccessingUnsetValues()
    {
        $claims = new Claims($this->data);

        $claims->get('not-included');
    }
}
