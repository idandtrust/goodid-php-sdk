<?php

namespace GoodID\Helpers;

/**
 * Implements 'Curve' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7518#section-6.2.1.1
 */
class Curve
{
    /**
     * P-256 Curve
     *
     * @var string
     */
    const CURVE_P256 = "P-256";

    /**
     * P-384 Curve
     *
     * @var string
     */
    const CURVE_P384 = "P-384";

    /**
     * P-521 Curve
     *
     * @var string
     */
    const CURVE_P521 = "P-521";
}
