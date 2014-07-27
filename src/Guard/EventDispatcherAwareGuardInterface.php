<?php

namespace Webspot\Firewall\Guard;

use Symfony\Component\EventDispatcher\EventDispatcher;

interface EventDispatcherAwareGuardInterface extends GuardInterface
{
    /**
     * @param   EventDispatcher $eventDispatcher
     * @return  void
     */
    public function setEventDispatcher(EventDispatcher $eventDispatcher);
}
