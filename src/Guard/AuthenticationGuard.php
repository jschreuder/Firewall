<?php

namespace Webspot\Firewall\Guard;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Webspot\Firewall\Event\AuthenticationEvent;
use Webspot\Firewall\Event\CreateTokenEvent;
use Webspot\Firewall\Event\ResponseEvent;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Exception\UnauthorizedException;
use Webspot\Firewall\Firewall;

class AuthenticationGuard implements EventDispatcherAwareGuardInterface
{
    const TOKEN_USER_ID = 'fwl:uid';

    /** {@inheritdoc} */
    public static function getSubscribedEvents()
    {
        return [
            Firewall::EVENT_VALIDATE_REQUEST => ['validateRequest', 0],
            Firewall::EVENT_AUTHENTICATE => ['authenticateUser', 0],
            Firewall::EVENT_SEND_RESPONSE => ['addAuthChallengeForUnauthorized', 128],
            Firewall::EVENT_CREATE_TOKEN => ['addUserToToken', -256],
        ];
    }

    /** @var  EventDispatcher */
    private $eventDispatcher;

    /** @var  callable */
    private $authenticator;

    /** @var  string */
    private $userId;

    /**
     * Needs a callable that will accept both a $username & $password parameter
     * and return the UserID when valid or null when invalid
     *
     * @param  callable $authenticator
     */
    public function __construct(callable $authenticator)
    {
        $this->authenticator = $authenticator;
    }

    /**
     * @param   EventDispatcher $eventDispatcher
     * @return  void
     */
    public function setEventDispatcher(EventDispatcher $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /** @return  EventDispatcher */
    protected function getEventDispatcher()
    {
        return $this->eventDispatcher;
    }

    /**
     * @param   string $username
     * @param   string $password
     * @return  string
     */
    protected function authenticate($username, $password)
    {
        return call_user_func($this->authenticator, $username, $password);
    }

    /**
     * Sees if there's a user to authenticate and trigger EVENT_AUTHENTICATE if so
     *
     * @param   ValidationEvent $event
     * @return  void
     */
    public function validateRequest(ValidationEvent $event)
    {
        $request = $event->getRequest();

        $authenticationEvent = new AuthenticationEvent($request);
        $this->getEventDispatcher()->dispatch(Firewall::EVENT_AUTHENTICATE, $authenticationEvent);

        if ($authenticationEvent->isAuthenticated()) {
            $this->userId = $authenticationEvent->getUserId();
        } else {
            $event->setState(ValidationEvent::STATE_REFUSED);
            $event->setMessage('Authentication failed');
            $event->setException(new UnauthorizedException());
        }
    }

    /**
     * Authenticates the user
     *
     * @param   AuthenticationEvent $event
     * @return  void
     */
    public function authenticateUser(AuthenticationEvent $event)
    {
        $username = $event->getUsername();
        $password = $event->getPassword();
        if (empty($username) || empty($password)) {
            return;
        }

        $userId = $this->authenticate($username, $password);
        if ($userId) {
            $event->setUserId($userId);
        }
    }

    public function addAuthChallengeForUnauthorized(ResponseEvent $event)
    {
        $response = $event->getResponse();
        if ($response->getStatusCode() === 401) {
            $response->headers->set('WWW-Authenticate', 'Basic realm="Webspot"'); // @todo make this configurable
        }
    }

    /**
     * Adds the authenticated User's ID to the JWT
     *
     * @param   CreateTokenEvent $event
     * @return  void
     */
    public function addUserToToken(CreateTokenEvent $event)
    {
        $event->getJwt()->custom($this->userId, self::TOKEN_USER_ID);
    }
}
