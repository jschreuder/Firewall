<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class TokenValidatedEvent extends Event
{
    /** @var  string */
    private $token;

    /** @var  Request */
    private $request;

    public function __construct($token, Request $request)
    {
        $this->token = $token;
        $this->request = $request;
    }

    /** @return  Request */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param   string $token
     * @return  void
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /** @return  string */
    public function getToken()
    {
        return $this->token;
    }
}
