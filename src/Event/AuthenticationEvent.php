<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class AuthenticationEvent extends Event
{
    /** @var  Request */
    private $request;

    /** @var  int|mixed */
    private $userId;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /** @return  Request */
    public function getRequest()
    {
        return $this->request;
    }

    /** @return  string */
    public function getUsername()
    {
        return $this->getRequest()->getUser();
    }

    /** @return  string */
    public function getPassword()
    {
        return $this->getRequest()->getPassword();
    }

    /**
     * @param   int|mixed $userId
     * @return  void
     */
    public function setUserId($userId)
    {
        $this->userId = $userId ?: null;
    }

    /** @return  array */
    public function getUserId()
    {
        return $this->userId;
    }

    /** @return  bool */
    public function isAuthenticated()
    {
        return !is_null($this->getUserId());
    }
}
