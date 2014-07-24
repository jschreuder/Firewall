<?php

namespace Webspot\Firewall\Exception;

class UnauthorizedException extends FirewallException
{
    public function __construct($message = '', \Exception $previous = null)
    {
        parent::__construct($message, 401, $previous);
    }
}
