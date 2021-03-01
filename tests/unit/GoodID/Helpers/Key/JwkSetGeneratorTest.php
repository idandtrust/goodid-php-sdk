<?php
namespace GoodID\Helpers\Key;
use GoodID\Helpers\Http\HttpResponse;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;
class JwkSetGeneratorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function itCanGenerateJwksUriContentWithoutExistingJwksUri()
    {        
        $sigPubKey = new RSAPublicKey($this->sigPubKey, array('use' => 'sig', 'kid' => 'sig-test'));
        $encPrivKey = new RSAPrivateKey($this->encPrivKey, array('use' => 'enc', 'kid' => 'enc-test'));

        $jwkSetGenerator = $this->createJwkSetGenerator();
        $jwkSetGenerator->addKey($sigPubKey);
        $jwkSetGenerator->addKey($encPrivKey);
        $this->assertJsonStringEqualsJsonString(
            $this->jwksUriContent,
            $jwkSetGenerator->generate());
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Duplicate use-kid pair!
     */
    public function itFailsIfMultipleKeysHaveSameUseAndKid()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey, array('use' => 'sig', 'kid' => 'sig-test'));

        $jwkSetGenerator = $this->createJwkSetGenerator();
        $jwkSetGenerator->addKey($sigPubKey);
        $jwkSetGenerator->addKey($sigPubKey);

        $jwkSetGenerator->run();
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Missing required keys.
     */
    public function itFailsIfSigKeyNotExists()
    {
        $sigPubKey = new RSAPublicKey($this->sigPubKey, array('use' => 'sig', 'kid' => 'sig-test'));

        $jwkSetGenerator = $this->createJwkSetGenerator();
        $jwkSetGenerator->addKey($sigPubKey);

        $jwkSetGenerator->run();
    }

    /**
     * @test
     *
     * @expectedException \GoodID\Exception\GoodIDException
     * @expectedExceptionMessage Missing required keys.
     */
    public function itFailsIfEncKeyNotExists()
    {
        $encPubKey = new RSAPublicKey($this->encPrivKey, array('use' => 'sig', 'kid' => 'enc-test'));

        $jwkSetGenerator = $this->createJwkSetGenerator();
        $jwkSetGenerator->addKey($encPubKey);

        $jwkSetGenerator->run();
    }

    /**
     * Partial mock
     *
     * @param HttpResponse $response
     * @return JwkSetGenerator
     */
    private function createJwkSetGenerator(HttpResponse $response = null)
    {
        $jwkSetGenerator = $this->getMockBuilder(JwkSetGenerator::class)
            ->setMethods(['callEndpoint'])
            ->getMock();
        $jwkSetGenerator->method('callEndpoint')
            ->willReturn($response);
        return $jwkSetGenerator;
    }

    private $sigPubKey =
'-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv5pUbc0tbzU6GCB0/ja+
UTCx9AFqNsKjS/nqKzzHbpXF//XbONjkYV7xQfV4D/a+FbAvQqJidR8P3ndb2zfZ
3xuZDd6hzHBMf3GtQldDS2y1/JPhdKLG5/rbjOke9b8mR/zqq8fo+GK0njffAEIQ
y4P5J50ANFx+8X6UulNUQ/AU/qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9+m
PfSDrvvGK9/O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt++
MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3
WQIDAQAB
-----END PUBLIC KEY-----';
    private $encPrivKey =
'-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1OfO1Si54G0DvrNMJrH8+VeP9Oti1bmm/gPcGN0HKCbRxwtW
Wfmh2ktwyBZx1UdCFU8NEbBs1UACR5ipNtfoTmekpe4rFajvHDSiW1Fcun2oizoW
QuRN/og25r/DL1s0C5aiLkFK5wt4mwGYC5DV5rYbEDX6/RzftaLNG1ZAQQv/gcNo
5quGXT79C/qK9M8YLFtQ6Ql1FWhJ6r/leNdmTZxWkyhW+eswTd2XlclzBH2YEm+G
LQ6FbXLj47+zvruclg8odzQWfQx7/+fxksqAc7PVkR1pIw83GoV1MQuZgDSvFce0
j/2dM5cc5yuaNQ9iCWDtDSAuWOFefaKTf768ywIDAQABAoIBAQCtkwdHNVrFI1to
P9kXuwhZaA/PR5BeWmtQsGjiRGCvVWa1dgLCfAh+Zf7ewZ2wmdXAdaBcCY/RE8xH
/qgGNGQKd+j99nxdvkqini63cE+/Iu8kAwlfI66KkxbfbPt+QkbeI8K5HzYnw2xi
QxxoYX5iB5lsz/V+IeootT+ux9S+scEwfwzqQmehX9PKDCp/MA6JytHgPjgBF7Vd
4NBhUHGtSwZDjmMQB5LR83RIeaRx61U+k+arDa3FqzkvYZ6vQeZBX+AWZLhzZuaZ
6acWIxrpavcrB81q25gAC26kpdhLnyQXkUyDGlQnx2asy3BUT3Mg0tWOCMg2olOa
wB5gk3cRAoGBAP+wR164bXtE6n3c9NhA5EVwmhS2VPjv1n3oExW/UCovxTYJnW7U
YmlL7BFZaE1lEsrMVBZ/vYx3EkRaNYemWnIXDoJia17/+l1PHFyE4zvcTicocQBg
sZTf7YFI5UTQK3+m+X8981xFZEkfrA6Gj1172LKCJpWBqR/gIMYsMPS/AoGBANUq
MJbFTmRPdievbgMQ20gN5nSnYfe8vKXzQXcuOy6sY2FwCkRAvIAWvIgCTKyOz8JF
/wvoXOE4Q0li8lXLbaAxhr24YmsJqSHvaqFF7p9TqvEVuLiDJ2RTqhlWEduYL/om
Zu0h8NgTqL+7QrqW/rPu0LDTo3KvelqhNQ8Wsf71AoGATK7KiM7ZDto5VWwaBm1X
yLefjkysqUgM1Q/wAVqyKSTQiYdSrvWFWj0J3J4q2ONSQn4LTgAbke/4C4XefgNX
JtZhZJstxn0Q0kEyqVC1cbN9wOKxGULmn1aVPWvmTr/7+7nRI+cpgGfTTtbv3B9h
CdFlyQudlMMhPM0UJzsDp7MCgYAAiI5+khfUIG7HQqUf1Nb3ozFEcXbJS+uc7rLn
PXJgd4X4JHOiIBdYqrXmETtn4yOZ9NriiL5SwfVJJbo9hLjNgdI4f1GfuvJ1Z0f5
B1fFhkwTNl6z94ANvDfcwF5jEkpscdQoG8GiiMoPUMSl+uLASIS1LJJoIxBHUcf0
NbZUUQKBgGro6eUPiee4v5iB47ceCdrAwN8LQKd/xuTg68TKRO6RO1A/DuJbkluD
BJaKtsprQIrIAbnkxPLNx9iCwNteww8aOh0HJWEV/0t95rXWuKDmXriXO4++wyIA
XGMjP3IOvNn84lBTD+aJxUpNQmTbKDLqpPiWXncoa7CxnXsPjom/
-----END RSA PRIVATE KEY-----';
    private $jwksUriContent = '{"keys":[{"kty":"RSA","n":"v5pUbc0tbzU6GCB0_ja-UTCx9AFqNsKjS_nqKzzHbpXF__XbONjkYV7xQfV4D_a-FbAvQqJidR8P3ndb2zfZ3xuZDd6hzHBMf3GtQldDS2y1_JPhdKLG5_rbjOke9b8mR_zqq8fo-GK0njffAEIQy4P5J50ANFx-8X6UulNUQ_AU_qEsDQnmyxvmasgQhKeNHnwKmMYcYblpj5sLA9-mPfSDrvvGK9_O7wuwrrY73gir9z0aw3URwkYjzibuw71kcxRpp3A9GpQqfw9kDt--MU9lBho5InNZdMI4K6attCMQCePR869AaQ4LHx7NVZM0tp0284Ry4IWQQqQKKEv3WQ","e":"AQAB","use":"sig","kid":"sig-test","alg":"RS256"},{"kty":"RSA","n":"1OfO1Si54G0DvrNMJrH8-VeP9Oti1bmm_gPcGN0HKCbRxwtWWfmh2ktwyBZx1UdCFU8NEbBs1UACR5ipNtfoTmekpe4rFajvHDSiW1Fcun2oizoWQuRN_og25r_DL1s0C5aiLkFK5wt4mwGYC5DV5rYbEDX6_RzftaLNG1ZAQQv_gcNo5quGXT79C_qK9M8YLFtQ6Ql1FWhJ6r_leNdmTZxWkyhW-eswTd2XlclzBH2YEm-GLQ6FbXLj47-zvruclg8odzQWfQx7_-fxksqAc7PVkR1pIw83GoV1MQuZgDSvFce0j_2dM5cc5yuaNQ9iCWDtDSAuWOFefaKTf768yw","e":"AQAB","use":"enc","kid":"enc-test","alg":"RSA-OAEP"}]}';
}
