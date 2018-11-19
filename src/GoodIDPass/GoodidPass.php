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

namespace GoodIDPass;

use DateTimeImmutable;

class GoodidPass
{
    private $serial;
    private $lastModified;
    private $clientId;
    private $templateId;
    private $passUrl;
    private $associatedSubs;

    /**
     * @param string $serial
     * @param DateTimeImmutable $lastModified
     * @param string $clientId
     * @param string $templateId
     * @param string $passUrl
     * @param string array $associatedSubs
     */
    public function __construct(
        $serial,
        DateTimeImmutable $lastModified,
        $clientId,
        $templateId,
        $passUrl,
        array $associatedSubs
    ) {
        $this->serial = $serial;
        $this->lastModified = $lastModified;
        $this->clientId = $clientId;
        $this->templateId = $templateId;
        $this->passUrl = $passUrl;
        $this->associatedSubs = $associatedSubs;
    }

    /**
     * @return string
     */
    public function getSerial()
    {
        return $this->serial;
    }

    /**
     * @return DateTimeImmutable
     */
    public function getLastModified()
    {
        return $this->lastModified;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getTemplateId()
    {
        return $this->templateId;
    }

    /**
     * @return string
     */
    public function getPassUrl()
    {
        return $this->passUrl;
    }

    /**
     * @return array
     */
    public function getAssociatedSubs()
    {
        return $this->associatedSubs;
    }
}
