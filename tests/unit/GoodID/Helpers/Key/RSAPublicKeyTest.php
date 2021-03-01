<?php

namespace GoodID\Helpers\Key;

use Jose\Object\JWKInterface;

class RSAPublicKeyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreatedFromPem()
    {
        $key = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertInstanceOf(RSAPublicKey::class, $key);
    }

    /**
     * @test
     */
    public function itCanVerifySignatures()
    {
        $key = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));

        $expected = ['iss' => 'https://jwt-idp.example.com'];
        $payload = $key->verifyCompactJws($this->jws);
        $this->assertEquals($expected, $payload);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Can not verify signature: No payload.
     */
    public function itFailsWhenPayloadIsEmpty()
    {
        $key = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $key->verifyCompactJws($this->jwsEmptyPayload);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Can not verify signature: Unable to verify the JWS.
     */
    public function itFailsWhenSignatureIsWrong()
    {
        $key = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $key->verifyCompactJws($this->jwsDifferentSignature);
    }

    /**
     * @test
     */
    public function itCanGetThePublicKeyAsJwkArray()
    {
        $publicKey = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertEquals($this->publicKeyJwkArray, $publicKey->getPublicKeyAsJwkArray());
    }

    /**
     * @test
     */
    public function itCanGetTheKeyId()
    {
        $publicKey = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertEquals('test', $publicKey->getKid());
    }

    /**
     * @test
     */
    public function itCanBeConvertedToSpomkyKey()
    {
        $publicKey = new RSAPublicKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
        $spomkyKey = $publicKey->asSpomkyKey();

        $this->assertInstanceOf(JWKInterface::class, $spomkyKey);
        $this->assertEquals($publicKey->getPublicKeyAsJwkArray(), $spomkyKey->getAll());
    }

    private $publicKey = '
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5pUbc0tbzU6GCB0/ja+
UTCx9AFqNsKjS/nqKzzHbpXF//XbONjkYV7xQfV4D/a+FbAvQqJidR8P3ndb2zfZ
3xuZDd6hzHBMf3GtQldDS2y1/JPhdKLG5/rbjOke9b8mR/zqq8fo+GK0njffAEIQ
y4P5J50ANFx+8X6UulNUQ/AU/qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9+m
PfSDrvvGK9/O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt++
MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3
WQIDAQAB
-----END PUBLIC KEY-----';

    private $privateKey = '
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv5pUbc0tbzU6GCB0/ja+UTCx9AFqNsKjS/nqKzzHbpXF//Xb
ONjkYV7xQfV4D/a+FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1/JPh
dKLG5/rbjOke9b8mR/zqq8fo+GK0njffAEIQy4P5J50ANFx+8X6UulNUQ/AU/qEs
DQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9+mPfSDrvvGK9/O7wuwrrY73gir9z0a
w3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt++MU9lBho5InNZdMI4K6attCMQCePR
869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQIDAQABAoIBAQCFheBGcJC0CgzF
GYFOUwoH/H5Ww9Gn/bXc0XmNzhpRB1DnUgcGs6db79UDGTQlM9c9t/0HW7BvXEkr
yFQcDezn3QypLLfmh2/X9HlAXR2JZ2XfcZLRPEqPCTONHDw2F5Ju4mMLeRHyXp7u
D5N5U5DusrakE3Y8ByVz17l/q2hyupyykwqUJCgRvVK8o3H3XP+fLHYiZladgNg6
sEE0CbQODmccVZB1J0oNJtQJFkk9TSPeaN6U1twXTOKClAB5Z3tHcgQUAza8ra8g
KVuGFadcv52bRHB/BsWMyT8qqrzxiS6Nfnt6vkvzlMFgN2hHXR+aq1pw+q0TOu/P
BxgXBJZtAoGBAOK4kXr0N55QEn3B2yNakPYUahav2/tNJ4gDsUQaFVZX17eziZb6
pO1chQySFgCjjWLWVn0SlAzeI7vvzbHwd1E1IjwetspRYHEVkiNxf3jtGFDFz9Wm
sv4nXZ788lqMs2mb4NI+YaqBz/MafqxwB1re/p1SwIo4OZwJt1jWP6Z/AoGBANhY
wDgIUiUFoxHvTJJur6pZQX7Jpq+iqtwbPPopMrMAhxm8Isq8TgFbi026mTYxC7SY
k1xDBhCiJKvdKyljsGpMZRQAclAVhvP12suoU+zYmVaRdIZoT4kPmHhbtb7B8huI
MxNjHoq7i5ODrTbQkDkn9H1XfIZhTL/uPuCEPWYnAoGBANIdnW4m4VjN+qUjwPSd
3ZTBzKQj7SqUEZvjWCi2R6oSlPBB6rTKq4jzYrcIuG11JfZAkD0vt5fJU7K8BpTv
N5VCOe0fxeXwzwFerWY9rJaknRFWkkv+Rwp17zUGVZEHrsqkVRJkD92WmuNBXb5v
wNE9sxiYdapjeziaZJpnTOv/AoGAUe16DT4JbX+u+zG1u5Yy672VMeBHQSfGsEeY
VduYGXVPtA0s171rhNQX8r2BG6aDGkbVNxEikNX2MSc2GxxnSDnZ5TMuFumwC17F
Fm6OKZj0qHW4vNVvmSXQxXNlZfGoL4jqXqMgg8T13Ez3IVTl6N8alQS2YWUjXWNp
aDhrz+0CgYEAkAF7WpclKxY/YcpBw65i8qqrtLM1J3DxP/eB9WGpggwagyIe6y5c
6TR+NIWBJjGM+m1FfYsl5CYdXbSW9o5qgMf/EWFlDhQDc/td6kBuXlAJ7yt1OD68
4HynUkRp/eyNXxA8kK0LOAxiUJyQAj1MjNcO3TWH4gO/w1kTbTNRjdQ=
-----END RSA PRIVATE KEY-----';

    private $publicKeyJwkArray = [
        'kty' => 'RSA',
        'n' => 'v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ',
        'e' => 'AQAB',
        'use' => 'sig',
        'kid' => 'test',
        'alg' => 'RS256'
    ];

    private $jws = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20ifQ.QcG85FlQo2_y0fAVTpggGlyahk-WoyuhJVl3I3VUnXBbEk2aJgnMqCx0kLLEDfwzNsgUtHrFACfXBaep0cu99qpOQ-4QbLWzNgaoH7s2a91vbqYcuI31b9j_S_SMeki1La92XSg2npALq782mYZgyxu497Ez_bXkq42NW97RaiKmpuChxM_PSgQdRADFOjeeEdRua_DBdDT_7un4AsT5fM_0kc9cQmJPMsX8j1yq-ULgIN3lQZ9qQiO2R8wo86FFMH8FA1yHPOX4-LzQyJObFqpczFGbbvLAiOn98xxjw5n2VpmpoVnDAMj3taQ88mpU69tKY3gnerXkm5qwHnw_kw';
    private $jwsEmptyPayload = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.ifKf3w8rhwcKRxIzyxGaOekEm_HxrC4ZogAzqAkXG2O4tPWbSQWVy8sFM9jKxzzoCwOClgJDRjIEYP8qQRZJLEDoae2wYDWUb8oLP9Hw8ENPtNv6FB28Sc_e4NI5OpYN0YOSopUuqFqZFf88Ma7h2tby_puuzP1BUuqECFZUftU5bW8cvGuJsERmx8-y3CULN87ctx9av9qLrnQ_r91zXlyWkmEaV1jLlZltbm9QGHVf16Q4_d0F2poqroywczjZPoWihU8vJelKL5Su-rjX7dNd7nc3ItmnXzF5qoN4yDHsECidgGWbiReAhO150o6_-1M4TAwxW7ijGqL8wpBc_w';
    private $jwsDifferentSignature = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20ifQ.WZsYEUkQrV0tC0OkFUw5vnp2GU6uRmhsE2vNaF58vkAEbzzRVwRpmO_vrxUIvsLVgbRaK6ntGUb0jUV34tD_bBK0-SnbKMceh0gFqU3jOwAqIJjdZ5nSzs86EuDInQeliBSzOH7i-OG4t9qPVZJkNEjgj0AGdOyWlOs6-oriiqAGK11JJYREMeJImdU9XwIrmCB7zfS5n2lS31Yrnic1nDyD0DFZJuJZV-BsmPYCKozJ929IjbJUd-QxhQczA3E3Pm73bZwaKPmp5YHseHWHiz7iCrXhJqIrE-PEJ7NLbFVbUBrPt_7i3iIsqv2WMSCEpkq9mZbW9kUbUQcnE1byFQ';
}
