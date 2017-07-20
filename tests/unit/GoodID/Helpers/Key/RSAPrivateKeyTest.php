<?php

namespace GoodID\Helpers\Key;

class RSAPrivateKeyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
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
        $key = new RSAPrivateKey($this->publicKey);
    }

    /**
     * @test
     */
    public function itCanSignPayload()
    {
        $key = new RSAPrivateKey($this->privateKey);
        $payload = ['iss' => 'https://jwt-idp.example.com'];
        $this->assertEquals($this->jws, $key->signAsCompactJws($payload));
    }

    /**
     * @test
     */
    public function itCanDecryptPayload()
    {
        $payload = 'payload to encrypt';
        $key = new RSAPrivateKey($this->privateKey);

        $this->assertEquals($payload, $key->decryptCompactJwe($this->jwe));
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Can not decrypt: Unable to decrypt the JWE.
     */
    public function itFailsWhenUsingWrongKey()
    {
        $key = new RSAPrivateKey($this->privateKey);
        $key->decryptCompactJwe($this->jweEncryptedWithDifferentKey);
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

    private $jws = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvand0LWlkcC5leGFtcGxlLmNvbSJ9.cHUDZnkiTeTofk-6TVbpdQZ2fdKHUt4uIeoj4gXm-5x9GDdHGEvgklgoWQVfdZV_srVm1g8rNtEtXklx6TFPCuosj0Wiv4U-5HRk5FUI0bCEQg_hKNb3bvCgiTRXhkgfN1X7Z7JXu2kd8eOBeHGuyPTjqaKp8i8QUX_C-Wm2WaDBMYGBHvsQi9RmFqDt79jS371PmXlxRSzM6rdPwYU_7g86gf2-Ow_Zwhq80WfAXlvLbF-PssifVQ-zitohIT8hYQMQ6wizyIhDbHNQ707sm8HtwzB1tajVqySumfumluwdj-y8V2f56UxENEj5v7JzwvhHnmFuw1_cdS1XXynvKw';
    private $jwe = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ6aXAiOiJERUYifQ.o7srqwh27F-yEPwPfETE_75mJ2qVfmVPqz9kyPSShN9zOZMOOfCkK654tEFx9B9uqQbXvk-HS6CqGsVVbcgwqAKEztw5XKC-UzUnSmzTljcxDYllSW5UcovGa8TmBCPJ540IQY0hxYPs1Neyb1DEO_RVg6sPgt152pMGoeHig9k-9gENiH87BfhAhp7_ZQUWAgkwT06b4i8wlf320uMEulRseuAxSTDg80w0z7PAFlniGgfYAZdlbrLGraj7E-Y0rqGo-2mswpxIsFefgBOY2r43yEcgW98AexmR03Kx95CDjnVnDYa34dYUGp3siqdKSp23NEukvtCjlDPhujsV4g.lIn5EucmygjO6eyLBYFSnQ.gZx2Pf30FsGSQPfbHTR0sj8EvY5Yx6ChePrE-8WEEck.zouxUX_DmS2vfS0UpZCWH6i6FdxvMIEkfKwJgH_CViM';
    private $jweEncryptedWithDifferentKey = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ6aXAiOiJERUYifQ.BP9ziOuYjVkqHmehXaMVVnQSnfUu4au2c61WQVRq0n00dZEwCfVYvo14EilBv4p7lZ6LI8EVKNz9Ctf9t_uaWiG0PWhmXSFRIVvLHtIS4OFxYLzQUBNcLorPezX0J6kOm1t2U6Y5lyQYwLxIKTt1gH7LdsMPlaR-2vjq9TKqoGU_F9JTlHwyOjIRBfdsSpX7ZoXFrvmQSm80FUrQpF1RWz05pVyPSXQ1k6lL7v6ivHGPV3geULkQ4XDOdn4WfF306DOb0U39jMBhSW5Vc0sIN0wPkNKLpTS9aqE1gyhSp-AVqVvyeo76H-otitt495sf7SREA2RthZ7aQ227aGaFUw.IlKT4-KbfGWIT3YnYLKbRA.kPmUGBEpQ6TUZMHdr8J46U2uo00HCpRxLlZZc7rjAUY.WuV4bu8i3nIAbwDle5tPDww7_H0TLgfmFZc_WW0F4Ns';
}
