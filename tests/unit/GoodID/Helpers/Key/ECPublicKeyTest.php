<?php

namespace GoodID\Helpers\Key;

class ECPublicKeyTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid JWS string.
     */
    public function ifFailsWithInvalidJws()
    {
        ECPublicKey::verifySelfSignedCompactJws('not a jws');
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Missing sub_jwk.
     */
    public function itFailsWithMissingKey()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithMissingSubJwk);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid sub_jwk format.
     */
    public function itFailsWithInvalidKey()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithInvalidSubJwk);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid sub_jwk format.
     */
    public function itFailsWithInvalidKeytype()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithInvalidKeyType);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid sub_jwk format.
     */
    public function itFailsWithInvalidCurve()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithInvalidCurve);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid signature: sub vs sub_jwk mismatch.
     */
    public function itFailsWhenSubDiffersFromKeyThumbprint()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithSubKeyThumbprintMismatch);
    }

    /**
     * @test
     * @expectedException \GoodID\Exception\ValidationException
     * @expectedExceptionMessage Invalid signature.
     */
    public function itFailsWithInvalidSignature()
    {
        ECPublicKey::verifySelfSignedCompactJws($this->jwsWithInvalidSignature);
    }

    /**
     * @test
     */
    public function itReturnsClaimsWhenValidationSucceeds()
    {
        $claims = ECPublicKey::verifySelfSignedCompactJws($this->validJws);

        $this->assertTrue(is_array($claims));
        $this->assertCount(2, $claims);
        $this->assertArrayHasKey('sub', $claims);
        $this->assertArrayHasKey('sub_jwk', $claims);
    }

    private $jwsWithMissingSubJwk = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJiY05ULXpzX3ZJVEMtT0F2N0d4MUxqYjBWaUptclZlSXdSalpXVzhqX0RZIn0.G5K8UiVwC-1oGq1JZwzjv0cX8-9YkCfkwoajDzMRbtAaVf817Jm59WFkrRZ5YDcJAf3fL8mIIwM8XWdLbct6Ng';
    private $jwsWithInvalidSubJwk = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJEeU1ocm5DSEhTQmN5YTBSX28tbXZlbWdoZF83TW5UbEd3VFZ0ZVlyWjVBIiwic3ViX2p3ayI6WyJpbnZhbGlkIl19._twVJFKjR5UnPYNhJy8yIdCO0QhCNP174iOmTXO-6qEeQBdC4hdN9zZ0x183RcfbgG9zRkFKOyRdRxHN_ucWZw';
    private $jwsWithInvalidKeyType = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ6Vmk4MDlmWDRUd3FkRWJwZU0yT2NIenNsYlp3cWJPbThVZlVRQzBzVDVjIiwic3ViX2p3ayI6eyJrdHkiOiJpbnZhbGlkIn19.1bTe-LZe6fmD1z76sSYHqCvGn24A9mhXZ-JzwxVZ68THm6PKiHzdS_s3D7od0vvHCcYbJzWBV2H931DGrJWFLw';
    private $jwsWithInvalidCurve = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJDOVpWb2tTWVJCYXh6QjJFUkdRLTg3THk0WDU2VlpZSW9VVGJWSk9wZ3hVIiwic3ViX2p3ayI6eyJrdHkiOiJFQyIsImNydiI6ImludmFsaWQifX0.9WKSwLxCR5HtqFQcgllWnSsIgYNllHcQhfZjMSEomf6VGQZJ_m0m6sFC6WdgIrwxCvRhu6UiiQ8dyvoW_NOaCA';
    private $jwsWithSubKeyThumbprintMismatch = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJpbnZhbGlkIiwic3ViX2p3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6Il9KSjNFU29iNy1mRlhCM3FQVHhiOXc4MGFEODVxY2xlVGhmUnphUy1weDAiLCJ5IjoiNlRWSnk4QzVHeUhFUFpsMGNxZGxrQk4tTVdZcVJOc3BpSDJhSER4ZUppcyIsImFsZyI6IkVTMjU2In19.6nnGRyTzNiWw1Q7N9kwM7cw_gpBYgmfsFll9KSq5I-MyR7aZTpHN7Hg9E8ctSIAluBACUqI_hQNKYJM2C2D9cg';
    private $jwsWithInvalidSignature = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIta1dTOTczdzd6SDUzaDk3WGpGbzM5dzdnQjlBX25aSzRFRlIxaUY4blpzIiwic3ViX2p3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6Imt5UWIwRWpOckN0OXMyb2dyWnJQcFZfQUdqdUx6RzhFdGtxbHZVQnIxVE0iLCJ5IjoidWNEazMxRlBFeVU3ZEFEeU1PeFBoWUZBYmUtT0hWUHphNjkzWXpzNUthRSIsImFsZyI6IkVTMjU2In19.gMTpdG8odQIfDIDOcaiV9hnU4tMHXWZgI0zcTeCpRImrTlo65_PtrxKFUAYaLEoOHuhCm-GEcIKfqPoYM7q3Z';
    private $validJws = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJfV3VIUlBjSk1yY1hhMkNEeUg1Mm16dFJVLUJNc1plRkFtVDBOTHRrclZRIiwic3ViX2p3ayI6eyJrdHkiOiJFQyIsInVzZSI6InNpZyIsImNydiI6IlAtMjU2IiwieCI6IlcwVDZHYmF0Zll6eHlLdjRNRW9tcVBFTUg1SGJGNE5tVFJKa1BkUkxxc28iLCJ5IjoicXJBa0JrQ0RfWFF5UHA1UEw5QUtQZWZpRlhsVy1JX19QVk9vLVBfQ0RONCIsImFsZyI6IkVTMjU2In19.wEg1i7DXPiXTn5FL0Eh2hdbUAcloCX65h7Wgfm7Kyy8pnJKVHfKCMQx4aDypA4Ug0QjYNUzKrpzhLaH1ha093g';
}
