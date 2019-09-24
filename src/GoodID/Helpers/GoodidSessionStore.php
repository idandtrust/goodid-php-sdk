<?php

namespace GoodID\Helpers;

class GoodidSessionStore implements GoodidSessionStoreInterface
{
    private $sessionDirectory;

    public function __construct($sessionDirectory)
    {
        $this->sessionDirectory = $sessionDirectory;
    }

    /**
     * @return GoodidSession
     */
    public function createGoodidSession()
    {
        return new GoodidSession(uniqid('gsid_'));
    }

    /**
     * @param GoodidSession $session
     */
    public function storeGoodidSession(GoodidSession $session)
    {
        file_put_contents($this->getSessionFilePath($session->getId()), json_encode($session));
    }

    /**
     * @param string $sessionId
     * @return GoodidSession
     */
    public function loadGoodidSession($sessionId)
    {
        return GoodidSession::createFromJson(file_get_contents($this->getSessionFilePath($sessionId)));
    }

    /**
     * @param string $sessionId
     */
    public function clearGoodidSession($sessionId)
    {
        unlink($this->getSessionFilePath($sessionId));
    }

    private function getSessionFilePath($sessionId)
    {
        return $this->sessionDirectory . DIRECTORY_SEPARATOR . $sessionId;
    }
}
