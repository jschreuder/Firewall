<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class AllowedEvent extends Event
{
    /** @var  Request */
    private $request;

    /** @var  string */
    private $message;

    public function __construct(Request $request, $message)
    {
        $this->request = $request;
        $this->message = $message;
    }

    /** @return  Request */
    public function getRequest()
    {
        return $this->request;
    }

    /** @return  string */
    public function getMessage()
    {
        return $this->message;
    }
}
