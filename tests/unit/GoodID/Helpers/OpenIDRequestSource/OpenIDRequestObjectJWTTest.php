<?php

namespace GoodID\Helpers\OpenIDRequestSource;

use GoodID\Helpers\Key\RSAPublicKey;

class OpenIDRequestObjectJWTTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanBeCreated()
    {
        $request = new OpenIDRequestObjectJWT($this->jws);
        $this->assertInstanceOf(OpenIDRequestObjectJWT::class, $request);
    }

    /**
     * @test
     */
    public function itReturnsJwt()
    {
        $request = new OpenIDRequestObjectJWT($this->jws);
        $this->assertEquals($this->jws, $request->getJwt());
    }

    /**
     * @test
     */
    public function itRecognisesAndReportsJwe()
    {
        $request = new OpenIDRequestObjectJWT($this->jwe);

        $key = new RSAPublicKey($this->publicKey);
        $this->assertEquals(OpenIDRequestObjectJWT::CONTENT_IS_ENCRYPTED, $request->getClaims($key));
    }

    /**
     * @test
     */
    public function itExtractsClaimsFromJws()
    {
        $request = new OpenIDRequestObjectJWT($this->jws);
        $key = new RSAPublicKey($this->publicKey);

        $expectedClaims = [
            'userinfo' => [
                'email' => null,
            ]
        ];

        $this->assertEquals($expectedClaims, $request->getClaims($key));
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Unsupported JWT format.
     */
    public function itFailsWhenJwtIsNotRecognised()
    {
        $request = new OpenIDRequestObjectJWT('invalid-jwt');
        $key = new RSAPublicKey($this->publicKey);

        $request->getClaims($key);
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

    private $jws = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvand0LWlkcC5leGFtcGxlLmNvbSIsImNsYWltcyI6eyJ1c2VyaW5mbyI6eyJlbWFpbCI6bnVsbH19fQ.Lqxz5JF6-NBfkh9IagoMeWlACKpeX7CPW79YAOOQWHtcd-6gsz0FROdxsEUUVB60IJ0MbmiuSMTf6BZ2zkv81zVRz3tLcZDHEzsH1gN8btSCvBrLadKLIj8D_kILY9OYlx531XB-bjw6Idaojyn70NvYsDulM_bKxE-iudX-Y7dX5HnJu5zjmvNQHn0xBTU6Idj9sxJpcalAJHfu7UgpvmyPsJRtn6qe3Fc0ZXTpxFzmNXtk0eIOPw8A6_PmaTL0e4q1ovrAgmHWZcplIyRuXiBvaYc5y7fESyaoAxdzGpz0-qO9Z8tX0VzG72_jO-s5Gz2xPsDOzSf3-8CDQXDM9w';
    private $jwe = 'eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJ6aXAiOiJERUYifQ.o7srqwh27F-yEPwPfETE_75mJ2qVfmVPqz9kyPSShN9zOZMOOfCkK654tEFx9B9uqQbXvk-HS6CqGsVVbcgwqAKEztw5XKC-UzUnSmzTljcxDYllSW5UcovGa8TmBCPJ540IQY0hxYPs1Neyb1DEO_RVg6sPgt152pMGoeHig9k-9gENiH87BfhAhp7_ZQUWAgkwT06b4i8wlf320uMEulRseuAxSTDg80w0z7PAFlniGgfYAZdlbrLGraj7E-Y0rqGo-2mswpxIsFefgBOY2r43yEcgW98AexmR03Kx95CDjnVnDYa34dYUGp3siqdKSp23NEukvtCjlDPhujsV4g.lIn5EucmygjO6eyLBYFSnQ.gZx2Pf30FsGSQPfbHTR0sj8EvY5Yx6ChePrE-8WEEck.zouxUX_DmS2vfS0UpZCWH6i6FdxvMIEkfKwJgH_CViM';
}
