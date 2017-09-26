<?php

namespace GoodID\Helpers\OpenIDRequestSource;

use GoodID\Helpers\Key\RSAPublicKey;

class OpenIDRequestURITest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itReturnsItsRequestUri()
    {
        $uri = new OpenIDRequestURI('https://some.request.uri');
        $this->assertEquals('https://some.request.uri', $uri->getRequestUri());
    }

    /**
     * @test
     */
    public function itDownloadsAndExtractsContents()
    {
        $key = new RSAPublicKey($this->publicKey);

        $uri = $this->createMockUri($this->jws);

        $expected = [
            'iss' => 'https://jwt-idp.example.com',
            'claims' => [
                'userinfo' => [
                    'email' => null,
                ],
            ],
        ];
        $tokens = $uri->toArray($key);
        $this->assertEquals($expected, $tokens);
    }

    /**
     * @test
     */
    public function itReportsEncryptedJwt()
    {
        $key = new RSAPublicKey($this->publicKey);

        $uri = $this->createMockUri($this->jwe);

        $this->assertEquals(OpenIDRequestURI::CONTENT_IS_ENCRYPTED, $uri->toArray($key));
    }

    /**
     * @test
     */
    public function itReportsEncryptedJwt2()
    {
        $key = new RSAPublicKey($this->publicKey);

        $uri = $this->createMockUri($this->jwe);

        $this->assertEquals(OpenIDRequestURI::CONTENT_IS_ENCRYPTED, $uri->getClaims($key));
    }

    /**
     * @test
     */
    public function itExtractsClaims()
    {
        $key = new RSAPublicKey($this->publicKey);

        $uri = $this->createMockUri($this->jws);

        $this->assertEquals(
            [
                'userinfo' => [
                    'email' => null,
                ],
            ],
            $uri->getClaims($key)
        );
    }

    /**
     * Partial mock
     *
     * @return OpenIDRequestURI|\PHPUnit_Framework_MockObject_MockObject
     */
    private function createMockUri($uriContents)
    {
        $uri = $this->getMockBuilder(OpenIDRequestURI::class)
            ->setConstructorArgs(['https://some.request.uri'])
            ->setMethods(['retrieveUriContents'])
            ->getMock();
        $uri->method('retrieveUriContents')
            ->willReturn($uriContents);

        return $uri;
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
