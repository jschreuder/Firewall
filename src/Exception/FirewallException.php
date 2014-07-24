<?php

namespace Webspot\Firewall\Exception;

class FirewallException extends \RuntimeException
{
    public function __construct($message = '', \Exception $previous = null)
    {
        parent::__construct($message, 400, $previous);
    }
}
