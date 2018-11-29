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
use DateTimeInterface;
use GoodIDPass\PassApi\GoodidPassApiInterface;

class GoodidPassService
{
    /**
     * @var GoodidPassApiInterface $passApi
     */
    private $passApi;

    /**
     * @param GoodidPassApiInterface $passApi
     */
    public function __construct(GoodidPassApiInterface $passApi)
    {
        $this->passApi = $passApi;
    }

    /**
     * @param string $templateId
     * @param string $passUrl
     *
     * @return GoodidPass
     */
    public function createPass($templateId, $passUrl)
    {
        $passData = $this->passApi->issuePass($templateId, $passUrl);
        return $this->mapArrayToPass($passData);
    }

    /**
     * @param $serial
     *
     * @return GoodidPass
     */
    public function retrievePass($serial)
    {
        $passData = $this->passApi->getPass($serial);
        return $this->mapArrayToPass($passData);
    }

    /**
     * @param string $serial
     * @param string|null $passUrl
     *
     * @return GoodidPass
     */
    public function updatePass($serial, $passUrl = null)
    {
        $passData = $this->passApi->updatePass($serial, $passUrl);
        return $this->mapArrayToPass($passData);
    }

    /**
     * @param string $serial
     * @param string|null $data
     *
     * @return string
     */
    public function getPassDownloadLink($serial, $data = null)
    {
        $passLinkData = $this->passApi->getPassDownloadLink($serial, $data);
        return $passLinkData['passDownloadLink'];
    }

    /**
     * @param string $serial
     * @param string $language
     * @param string $recipient
     * @param array $data
     */
    public function sendEmailAboutPass($serial, $language, $recipient, array $data)
    {
        $this->passApi->sendEmailAboutPass($serial, $language, $recipient, $data);
    }

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return GoodidPass
     */
    public function associatePassWithSub($serial, $sub)
    {
        $passData = $this->passApi->associatePassWithSub($serial, $sub);
        return $this->mapArrayToPass($passData);
    }

    /**
     * @param string $serial
     * @param string $sub
     *
     * @return GoodidPass
     */
    public function dissociatePassFromSub($serial, $sub)
    {
        $passData = $this->passApi->dissociatePassFromSub($serial, $sub);
        return $this->mapArrayToPass($passData);
    }

    /**
     * @param string $templateId
     *
     * @return GoodidPassTemplate
     */
    public function retrieveTemplate($templateId)
    {
        $templateData = $this->passApi->getPassTemplate($templateId);
        return $this->mapArrayToTemplate($templateData);
    }

    /**
     * @param array $data
     *
     * @return GoodidPass
     */
    private function mapArrayToPass(array $data)
    {
        return new GoodidPass(
            $data['serial'],
            DateTimeImmutable::createFromFormat('Y-m-d\TH:i:sO', $data['lastModified']),
            $data['clientId'],
            $data['templateId'],
            $data['passUrl'],
            $data['associatedSubs']
        );
    }

    /**
     * @param array $data
     *
     * @return GoodidPassTemplate
     */
    private function mapArrayToTemplate(array $data)
    {
        return new GoodidPassTemplate(
            $data['clientId'],
            $data['templateId'],
            $data['data']
        );
    }
}
