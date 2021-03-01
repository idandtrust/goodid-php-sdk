<?php

namespace GoodID\Helpers\Key;

class RSAPrivateKeyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanBeCreatedFromPem()
    {
        $key = new RSAPrivateKey($this->privateKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertInstanceOf(RSAPrivateKey::class, $key);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage This is not a private key.
     */
    public function itFailsWhenProvidedWithPublicKey()
    {
        new RSAPrivateKey($this->publicKey, array('use' => 'sig', 'kid' => 'test'));
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanSignPayload()
    {
        $key = new RSAPrivateKey($this->privateKey, array('use' => 'sig', 'kid' => 'test'));
        $payload = ['iss' => 'https://jwt-idp.example.com'];
        $this->assertEquals($this->jws, $key->signAsCompactJws($payload));
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanGetThePublicKeyAsJwkArray()
    {
        $privateKey = new RSAPrivateKey($this->privateKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertEquals($this->publicKeyJwkArray, $privateKey->getPublicKeyAsJwkArray());
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanGetTheKeyId()
    {
        $privateKey = new RSAPrivateKey($this->privateKey, array('use' => 'sig', 'kid' => 'test'));
        $this->assertEquals('test', $privateKey->getKid());
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

    private $jws = 'eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20ifQ.oK7saXJQi_wSmdsjHEy0VijIW01AJCN6WWLLAn1nERQRfbqXbqFoAbK72myIBgyTGdRxd1jxp6jgemu4yBLG-jxdL5ylin3WvE3iQ-DRI3ussakH2hjQeQU8uOdIvZJ6WZmrBozfUVftGwWKLKlSGmtWZwy0RRwhtsVhEjIf4DIJrxs71tCo5cxD1eP4BAe51qaiJJjw8_8uAt36FrDSZDzqCofjArqYoHIhSlexblVic3i6Bg4XRhOUxKogvK-68neJj6o4s8wkM--2UgaQAe46OLc5l2gI4TLCFuuvOVBM1Spy1DUblehl6kRyZfYil_75qWoR5nARx-ZV_qYxcg';
}
