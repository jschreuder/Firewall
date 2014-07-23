<?php

namespace Webspot\Firewall;

class FirewallException extends \RuntimeException
{
    public function __construct($message = '', \Exception $previous = null)
    {
        parent::__construct($message, 403, $previous);
    }
}
