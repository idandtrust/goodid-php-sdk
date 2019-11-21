<?php

namespace GoodID\Helpers\OpenIDRequestSource;

use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;

class OpenIDRequestObjectTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanBeCreatedFromArray()
    {
        /* @var RSAPublicKey|\PHPUnit_Framework_MockObject_MockObject $mockKey */
        $mockKey = $this->createMock(RSAPublicKey::class);
        $claims = [
            'sub' => 'some-subject-id',
            'name' => 'John Doe',
        ];

        $request = new OpenIDRequestObject($claims);
        $this->assertInstanceOf(OpenIDRequestObject::class, $request);
        $this->assertEquals($claims, $request->getClaims($mockKey));
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanBeCreatedFromJson()
    {
        /* @var RSAPublicKey|\PHPUnit_Framework_MockObject_MockObject $mockKey */
        $mockKey = $this->createMock(RSAPublicKey::class);
        $claims = '{"sub": "some-subject-id", "name": "John Doe"}';
        $request = new OpenIDRequestObject($claims);

        $this->assertInstanceOf(OpenIDRequestObject::class, $request);
        $this->assertEquals(
            [
                'sub' => 'some-subject-id',
                'name' => 'John Doe',
            ],
            $request->getClaims($mockKey)
        );
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itCanBeTurnedIntoAnArray()
    {
        $request = new OpenIDRequestObject([]);

        /* @var GoodIDServerConfig|\PHPUnit_Framework_MockObject_MockObject $serverConfig */
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getAudienceUri')
            ->willReturn('https://server.audience.uri');

        $this->assertEquals(
            [
                'iss' => 'a-client-id',
                'aud' => 'https://server.audience.uri',
                'response_type' => 'code',
                'client_id' => 'a-client-id',
                'redirect_uri' => 'https://a.redirect.url',
                'scope' => 'openid',
                'claims' => [],
            ],
            $request->toArray('a-client-id', 'https://a.redirect.url', $serverConfig)
        );
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itPreservesRequestedMaxAge()
    {
        $request = new OpenIDRequestObject([]);

        /* @var GoodIDServerConfig|\PHPUnit_Framework_MockObject_MockObject $serverConfig */
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getAudienceUri')
            ->willReturn('https://server.audience.uri');

        $this->assertEquals(
            [
                'iss' => 'a-client-id',
                'aud' => 'https://server.audience.uri',
                'response_type' => 'code',
                'client_id' => 'a-client-id',
                'redirect_uri' => 'https://a.redirect.url',
                'scope' => 'openid',
                'max_age' => 3600,
                'claims' => []
            ],
            $request->toArray('a-client-id', 'https://a.redirect.url', $serverConfig, 3600)
        );
    }

    /**
     * @test
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage max_age can not be negative
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itThrowsWhenNegativeMaxAgeRequested()
    {
        $request = new OpenIDRequestObject([]);

        /* @var GoodIDServerConfig|\PHPUnit_Framework_MockObject_MockObject $serverConfig */
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getAudienceUri')
            ->willReturn('https://server.audience.uri');

        $request->toArray('a-client-id', 'https://a.redirect.url', $serverConfig, -3600);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Claims parameter must be string (JSON) or array.
     */
    public function itFailsWhenClaimsIsInvalid()
    {
        new OpenIDRequestObject(null);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Can not decode claims JSON.
     */
    public function itFailsWhenClaimsIsInvalidJson()
    {
        new OpenIDRequestObject('{');
    }

    /**
     * @test
     * @throws \GoodID\Exception\GoodIDException
     */
    public function itGeneratesJwt()
    {
        $request = new OpenIDRequestObject([
            'id_token' => [
                'auth_time' => [
                    'essential' => true,
                ]
            ],
            'userinfo' => [
                'name' => [
                    'essential' => true,
                    'value' => 'John Doe',
                ],
                'email' => [
                    'essential' => true,
                ]
            ]
        ]);
        $signingKey = new RSAPrivateKey($this->privateKey);
        /* @var GoodIDServerConfig|\PHPUnit_Framework_MockObject_MockObject $serverConfig */
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getAudienceUri')
            ->willReturn('https://server.audience.uri');

        $jwt = $request->generateJwt($signingKey, 'a-client-id', 'https://a.redirect.url', $serverConfig);
        $this->assertEquals($this->jwt, $jwt);

        $pubKey = new RSAPublicKey($this->publicKey);
        $payload = $pubKey->verifyCompactJws($jwt);
        $this->assertEquals(
            [
                'iss' => 'a-client-id',
                'aud' => 'https://server.audience.uri',
                'response_type' => 'code',
                'client_id' => 'a-client-id',
                'redirect_uri' => 'https://a.redirect.url',
                'scope' => 'openid',
                'claims' => [
                    'id_token' => [
                        'auth_time' => [
                            'essential' => true,
                        ],
                    ],
                    'userinfo' => [
                        'name' => [
                            'essential' => true,
                            'value' => 'John Doe',
                        ],
                        'email' => [
                            'essential' => true,
                        ]
                    ]
                ],
            ],
            $payload
        );
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

    private $jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkZwYV9jIn0.eyJpc3MiOiJhLWNsaWVudC1pZCIsImF1ZCI6Imh0dHBzOi8vc2VydmVyLmF1ZGllbmNlLnVyaSIsInJlc3BvbnNlX3R5cGUiOiJjb2RlIiwiY2xpZW50X2lkIjoiYS1jbGllbnQtaWQiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2EucmVkaXJlY3QudXJsIiwic2NvcGUiOiJvcGVuaWQiLCJjbGFpbXMiOnsiaWRfdG9rZW4iOnsiYXV0aF90aW1lIjp7ImVzc2VudGlhbCI6dHJ1ZX19LCJ1c2VyaW5mbyI6eyJuYW1lIjp7ImVzc2VudGlhbCI6dHJ1ZSwidmFsdWUiOiJKb2huIERvZSJ9LCJlbWFpbCI6eyJlc3NlbnRpYWwiOnRydWV9fX19.g_jMiRIGPFugi0xANRWWU-LC9pLirWvWwh0Z50iFB6TdZ3u6FBethAh7PCOKUavg8jVK3kFPdr9pEAd2jm15Hm9ZhiVeUDuWpJLgeTgz-ymtVanZ_NBAfMPEj56zkVfU6gdfzO8mtB72iZM_jUa8SpqOhGUbprAXlGJaLtPxtKuJtYaec65Ai-IfTJcHTp3cypRTsAmakGXi6l6psJfrWpS_0tauM2SQZHHAE_WLM42ExLyG7X2pnYyVs0vG5oirp6sHJw4OdUuRDDc6RRqLPNPn9oy7xoGMLItDVBqv7MRRKT96sWh3IAAaYnZpnFO-wBMT9AyBNdXJYkOXM8Mu9g';
}
