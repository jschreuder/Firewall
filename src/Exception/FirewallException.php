<?php

namespace Webspot\Firewall\Exception;

class FirewallException extends \RuntimeException
{
    public function __construct($message = '', $code = 400, \Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
