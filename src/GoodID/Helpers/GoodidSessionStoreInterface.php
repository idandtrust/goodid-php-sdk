<?php

namespace GoodID\Helpers;

interface GoodidSessionStoreInterface
{
    /**
     * @return GoodidSession
     */
    public function createGoodidSession();

    /**
     * @param GoodidSession $session
     */
    public function storeGoodidSession(GoodidSession $session);

    /**
     * @param string $sessionId
     * @return GoodidSession
     */
    public function loadGoodidSession($sessionId);

    /**
     * @param string $sessionId
     */
    public function clearGoodidSession($sessionId);
}