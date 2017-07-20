<?php

namespace GoodID\Testing;

use GoodID\Helpers\Request\IncomingRequest;

class MockIncomingRequest extends IncomingRequest
{
    private $method = 'GET';
    private $origin = '';
    private $parameters;

    /**
     * @param array $parameters
     */
    public function __construct($parameters = [])
    {
        $this->parameters = $parameters;
    }

    /**
     * @param string $method
     *
     * @return $this
     */
    public function setMethod($method)
    {
        $this->method = $method;

        return $this;
    }

    /**
     * @param string $origin
     *
     * @return $this
     */
    public function setOrigin($origin)
    {
        $this->origin = $origin;

        return $this;
    }

    /**
     * @param string $name
     * @param string $value
     *
     * @return $this
     */
    public function setParameter($name, $value)
    {
        $this->parameters[$name] = $value;

        return $this;
    }

    /**
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * @return string
     */
    public function getOrigin()
    {
        return $this->origin;
    }

    /**
     * @param string $name
     *
     * @return string
     */
    public function getStringParameter($name)
    {
        return isset($this->parameters[$name]) ? $this->parameters[$name] : '';
    }
}
