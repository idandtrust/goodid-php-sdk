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
        $key = new RSAPrivateKey($this->privateKey);
        $this->assertInstanceOf(RSAPrivateKey::class, $key);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage This is not a private key.
     */
    public function itFailsWhenProvidedWithPublicKey()
    {
        new RSAPrivateKey($this->publicKey);
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanSignPayload()
    {
        $key = new RSAPrivateKey($this->privateKey);
        $payload = ['iss' => 'https://jwt-idp.example.com'];
        $this->assertEquals($this->jws, $key->signAsCompactJws($payload));
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanGetThePublicKeyAsJwkArray()
    {
        $privateKey = new RSAPrivateKey($this->privateKey);
        $this->assertEquals($this->publicKeyJwkArray, $privateKey->getPublicKeyAsJwkArray());
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanGetTheKeyId()
    {
        $privateKey = new RSAPrivateKey($this->privateKey);
        $this->assertEquals('Fpa_c', $privateKey->getKid());
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
        'e' => 'AQAB'
    ];

    private $jws = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkZwYV9jIn0.eyJpc3MiOiJodHRwczovL2p3dC1pZHAuZXhhbXBsZS5jb20ifQ.bF9Et2YNPBYk8BtqI1RaEWX6dXtkbhZX0EOMW1Nd3JecOPh3Py8FevXuOHMP0v4BQYfRCAVM2V9VGXCojvfahpkul2kgGrZNql6fsQaWf0bYPkyBBZekl9zvpgSu_qA4u2WMTBQLZy2q6oU-Ke7uIDofrct0CcxN5YTwHT_QL5RgYJAyiPUDOWmYyZZpU_9vQ9SGDCNQ-YYCAk-griJaM3NThXrRepP15GbnAsi5NCiIaWoxDfAVjYji0r6yeoewtBLH1g3vwCo7Zv7760746I-eDSQ4IefXIoo191Fmxu_g17b-S_E__mPCM--6eE4bu4yAqT6W8GacwGdzePMibg';
}
