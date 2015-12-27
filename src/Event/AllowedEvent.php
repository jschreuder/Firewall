<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class AllowedEvent extends Event
{
    /** @var  Request */
    private $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /** @return  Request */
    public function getRequest()
    {
        return $this->request;
    }
}
