<?php

namespace Webspot\Firewall\Event;

use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\HttpFoundation\Request;

class AuthenticationEvent extends Event
{
    /** @var  Request */
    private $request;

    /** @var  array */
    private $user;

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
     * @param   array $user
     * @return  void
     */
    public function setUser(array $user)
    {
        $this->user = $user;
    }

    /** @return  array */
    public function getUser()
    {
        return $this->user;
    }

    /** @return  bool */
    public function isAuthenticated()
    {
        return !is_null($this->getUser());
    }
}
