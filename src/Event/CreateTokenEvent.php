<?php

namespace Webspot\Firewall\Event;

use Psecio\Jwt\Jwt;
use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Cookie;

class CreateTokenEvent extends Event
{
    /** @var  array|null */
    private $oldToken;

    /** @var  Jwt */
    private $jwt;

    public function __construct(array $oldToken = null, Jwt $jwt)
    {
        $this->oldToken = $oldToken;
        $this->jwt = $jwt;
    }

    /** @return  array */
    public function getOldToken()
    {
        return $this->oldToken;
    }

    /** @return  Jwt */
    public function getJwt()
    {
        return $this->jwt;
    }
}
