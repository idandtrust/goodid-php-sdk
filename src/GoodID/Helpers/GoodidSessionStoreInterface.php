<?php

namespace GoodID\Helpers;

interface GoodidSessionStoreInterface
{
    /**
     * @param int|null $ttl Seconds
     * @return GoodidSession
     */
    public function createGoodidSession($ttl = null);

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