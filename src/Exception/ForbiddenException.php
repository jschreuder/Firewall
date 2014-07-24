<?php

namespace Webspot\Firewall\Exception;

class ForbiddenException extends FirewallException
{
    public function __construct($message = '', \Exception $previous = null)
    {
        parent::__construct($message, 403, $previous);
    }
}
