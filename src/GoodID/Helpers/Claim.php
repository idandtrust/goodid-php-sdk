<?php
/**
 * Copyright 2017 ID&Trust, Ltd.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to
 * use, copy, modify, and distribute this software in source code or binary form
 * for use in connection with the web services and APIs provided by ID&Trust.
 *
 * As with any software that integrates with the GoodID platform, your use
 * of this software is subject to the GoodID Terms of Service
 * (https://goodid.net/docs/tos).
 * This copyright notice shall be included in all copies or substantial portions
 * of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

namespace GoodID\Helpers;

/**
 * Class Claim
 *
 * @link http://www.iana.org/assignments/jwt/jwt.xhtml JWT claims list
 * There are other claims supported by GoodID
 *
 * Only the architecturally important claims are declared here
 * All claims can simply be referred to by their names by the RP's code
 */
class Claim
{
    const NAME_ISSUER = "iss";
    const NAME_SUBJECT = "sub";
    const NAME_AUDIENCE = "aud";
    const NAME_AUTH_TIME = "auth_time";
    const NAME_ISSUED_AT = "iat";
    const NAME_EXPIRATION_TIME = "exp";
    const NAME_SUB_JWK = "sub_jwk";
    const NAME_CLAIMS = "claims";
}
