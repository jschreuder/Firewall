<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class TokenValidationEvent extends Event
{
    const STATE_VALIDATED = 1;
    const STATE_INVALID = 0;
    const STATE_ILLEGAL = -1;

    /** @var  string */
    private $token;

    /** @var  Request */
    private $request;

    /** @var  int */
    private $state = self::STATE_INVALID;

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

    /**
     * Modify the state, please note that setting it to STATE_VALIDATED is not overwritten by the default
     * token validator. The state starts out as STATE_INVALID and should only be set otherwise if that truly
     * is the case.
     *
     * @param   int $state
     * @return  void
     * @throws  \OutOfRangeException
     */
    public function setState($state)
    {
        if (!in_array($state, [self::STATE_VALIDATED, self::STATE_INVALID, self::STATE_ILLEGAL])) {
            throw new \OutOfRangeException('ValidationEvent state must be either STATE_ALLOWED or STATE_REFUSED.');
        }
        $this->state = $state;
    }

    /**
     * Returns whether the Token currently is considered valid
     *
     * @return  bool
     */
    public function isValid()
    {
        return $this->state === self::STATE_VALIDATED;
    }

    /**
     * When there was a token but it was deemed illegal, a potential hack attempt
     *
     * @return  bool
     */
    public function isIllegal()
    {
        return $this->state === self::STATE_ILLEGAL;
    }
}
