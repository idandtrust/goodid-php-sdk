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

use GoodID\Authentication\GoodIDResponseInterface;

final class GoodidResult
{
    /**
     * @var bool
     */
    private $success;

    /**
     * @var string
     */
    private $description;

    /**
     * @param bool $success
     * @param string|null $description
     */
    private function __construct($success, $description = null)
    {
        $this->success = (bool)$success;
        $this->description = $description;
    }

    /**
     * @param GoodIDResponseInterface $goodidResponse
     * 
     * @return \self
     */
    public static function createFromResponse(GoodIDResponseInterface $goodidResponse)
    {
        $self = new self($goodidResponse->isSuccessful());

        if (!$goodidResponse->isSuccessful() && method_exists($goodidResponse, 'getErrorDescription')) {
            $self->setErrorDescription($goodidResponse->getErrorDescription());
        }

        $self->setHeader();

        return $self;
    }

    /**
     * @param string $description
     * 
     * @return \self
     */
    public static function createErrorResponse($description)
    {
        $self = new self(false);
        $self->setErrorDescription($description);
        $self->setHeader();

        return $self;
    }

    /**
     * @param $e \Exception
     * 
     * @return \self
     */
    public static function createFromException(\Exception $e)
    {
        $self = new self(false);
        $self->setErrorDescription($e->getMessage());
        $self->setHeader();

        return $self;
    }

    /**
     * @param string $description
     */
    public function setErrorDescription($description)
    {
        if ($this->success) {
            throw new \Exception('Do not set error description in case of success result.');
        }

        $this->description = $description;
    }

    /**
     * @return string
     */
    public function get()
    {
        $result['success'] = $this->success;

        if ($this->description) {
            $result['error_description'] = $this->description;
        }

        return json_encode($result);
    }

    /**
     * @return void
     */
    public function setHeader()
    {
        header('goodid_result:' . $this->get());
    }
}