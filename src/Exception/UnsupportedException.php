<?php

namespace Webspot\Firewall\Exception;

class UnsupportedException extends FirewallException
{
    public function __construct($message = '', \Exception $previous = null)
    {
        parent::__construct($message, 400, $previous);
    }
}
