<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Response;

class SignOffEvent extends Event
{
    /** @var  Response */
    private $response;

    public function __construct(Response $response)
    {
        $this->response = $response;
    }

    /** @return  Response */
    public function getResponse()
    {
        return $this->response;
    }
}
