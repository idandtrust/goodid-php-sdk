<?php

namespace GoodID\Helpers\OpenIDRequestSource;

use GoodID\Helpers\SecLevel;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;

class OpenIDRequestObjectTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreatedFromArray()
    {
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
     */
    public function itCanBeCreatedFromJson()
    {
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
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Invalid security level: -1
     */
    public function itFailsWhenSecLevelIsInvalid()
    {
        $request = new OpenIDRequestObject([
            'sub' => 'some-subject-id',
            'name' => 'John Doe',
        ]);
        $signingKey = new RSAPrivateKey($this->privateKey);
        $invalidSecLevel = -1;
        $serverConfig = $this->createMock(GoodIDServerConfig::class);

        $request->generateJwt($signingKey, null, null, $serverConfig, $invalidSecLevel);
    }

    /**
     * @test
     */
    public function itGeneratesJwtWithSecLevelSet()
    {
        $request = new OpenIDRequestObject([
            'id_token' => [],
            'userinfo' => [
                'sub' => 'some-subject-id',
                'name' => 'John Doe',
            ]
        ]);
        $signingKey = new RSAPrivateKey($this->privateKey);
        $serverConfig = $this->createMock(GoodIDServerConfig::class);
        $serverConfig->method('getAudienceUri')
            ->willReturn('https://server.audience.uri');

        $jwt = $request->generateJwt($signingKey, 'a-client-id', 'https://a.redirect.url', $serverConfig, SecLevel::LEVEL_NORMAL);
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
                    ],
                    'userinfo' => [
                        'sub' => 'some-subject-id',
                        'name' => 'John Doe',
                    ]
                ],
                'sec_level' => SecLevel::LEVEL_NORMAL
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

    private $jwt = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkZwYV9jIn0.eyJpc3MiOiJhLWNsaWVudC1pZCIsImF1ZCI6Imh0dHBzOlwvXC9zZXJ2ZXIuYXVkaWVuY2UudXJpIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJjbGllbnRfaWQiOiJhLWNsaWVudC1pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOlwvXC9hLnJlZGlyZWN0LnVybCIsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7fSwidXNlcmluZm8iOnsic3ViIjoic29tZS1zdWJqZWN0LWlkIiwibmFtZSI6IkpvaG4gRG9lIn19LCJzZWNfbGV2ZWwiOjJ9.JZuStSicYNG5BTIXPkSXGm81mpYt1EaLlnXKuigcZMaq7i3f2K0GiZMbyzDfn-vICRwsdGQ7P_X_i1rWwmywi5KkY3PkDqEvStUn4LLsZeUhwqkYno3yqev5qKnE-PMnxy9wXQPVmc-TSsew88JRYd6sgS0W5ENvMY9VFYOYeNeu0ZbGrYoRtPH4qugSEECZ7ckuHUb5Uw7SddXIHyonIHVxisIvICoz34KmHKYUeURXTKE7KQXr6Nt5HtqCpPJnUZ8n9l5mBm1ld3zlrZ4Wwy3N-mYtc2alq_c8URwm6FsZyOMbGQnKm_bT2BKo6wisP-b_ltBHUjRXIEZUmodnGw';
    private $jwtWithSecLevel2 = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IkZwYV9jIn0.eyJpc3MiOiJhLWNsaWVudC1pZCIsImF1ZCI6Imh0dHBzOlwvXC9zZXJ2ZXIuYXVkaWVuY2UudXJpIiwicmVzcG9uc2VfdHlwZSI6ImNvZGUiLCJjbGllbnRfaWQiOiJhLWNsaWVudC1pZCIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOlwvXC9hLnJlZGlyZWN0LnVybCIsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7ImlkX3Rva2VuIjp7InNlY19sZXZlbCI6eyJ2YWx1ZSI6MX19LCJ1c2VyaW5mbyI6eyJzdWIiOiJzb21lLXN1YmplY3QtaWQiLCJuYW1lIjoiSm9obiBEb2UifX0sInNlY19sZXZlbCI6Mn0.Y3qQ-mQITja-aMjvSJSxzF3tOI9Bgbp_3iao3fbZjM3cDVaUsNCVqamH8VLGNJbRP13inxXiFpZHtoeuiDjN8WC1HKc4E9pqQOy3AIY2eCf_lYRfJ2-u7PkPkKbzrEspqj7B9pnGIWuR8aADXG16sPgQX5iHTUPMugmO_8WWqx2NWjMT66m4BzOXdDjbQK2Fv8F5kJAMisngvfTnMDSEdmSrKVx3VGlrklXUuDTKp1SuP2tgdCGOO3LtbUZ4N7QOr79TWrrCkIjxfLigdm84oUpeDizm7TvZLtGYXeRaTwPGmID3oQQuVNqFnjZuvHQ8y-84lEdILfSBoKavEsVrug';
}
