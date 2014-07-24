<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;
use Webspot\Firewall\Exception\FirewallException;

class ValidationEvent extends Event
{
    const STATE_ALLOWED = 1;
    const STATE_REFUSED = 0;

    /** @var  Request */
    private $request;

    /** @var  int */
    private $state;

    /** @var  string */
    private $message;

    /** @var  FirewallException */
    private $exception;

    public function __construct(Request $request, $initialState = self::STATE_ALLOWED)
    {
        $this->request = $request;
        $this->state = $this->validateStateValue($initialState);
    }

    /** @return  Request */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * Throws an exception when the state is invalid
     *
     * @param   int $state
     * @return  int
     * @throws  \OutOfRangeException
     */
    private function validateStateValue($state)
    {
        if (!in_array($state, [self::STATE_ALLOWED, self::STATE_REFUSED])) {
            throw new \OutOfRangeException('ValidationEvent state must be either STATE_ALLOWED or STATE_REFUSED.');
        }
        return $state;
    }

    /**
     * Modifying the state will always end propagation and return the given state as the end-state
     *
     * @param   int $state
     * @return  void
     */
    public function setState($state)
    {
        $this->state = $this->validateStateValue($state);
        if ($this->state === self::STATE_REFUSED) {
            $this->stopPropagation();
        }
    }

    /**
     * Returns whether the visitor currently is considered allowed
     *
     * @return  bool
     */
    public function isAllowed()
    {
        return $this->state === self::STATE_ALLOWED;
    }

    /**
     * Set the reason for failing or allowing for debug purposes, should never be shown to the visitor
     *
     * @param   string $msg
     * @return  void
     */
    public function setMessage($msg)
    {
        $this->message = $msg;
    }

    /**
     * Fetch the message
     *
     * @return  string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * @param   FirewallException $exception
     * @return  void
     */
    public function setException(FirewallException $exception)
    {
        $this->exception = $exception;
    }

    /** @return  FirewallException */
    public function getException()
    {
        return $this->exception;
    }
}
