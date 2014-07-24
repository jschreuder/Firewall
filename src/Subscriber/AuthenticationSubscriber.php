<?php

namespace Webspot\Firewall\Subscriber;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Webspot\Firewall\Event\AuthenticationEvent;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Firewall;
use Webspot\Firewall\FirewallSubscriberInterface;

class AuthenticationSubscriber implements FirewallSubscriberInterface
{
    /** {@inheritdoc} */
    public static function getSubscribedEvents()
    {
        return [
            Firewall::EVENT_VALIDATE_VISITOR => ['validateVisitor', 0],
            Firewall::EVENT_AUTHENTICATE => ['authenticateUser', 0],
            Firewall::EVENT_CREATE_TOKEN => ['addUserToToken', -256],
        ];
    }

    /** @var  EventDispatcher */
    private $eventDispatcher;

    /** @var  \PDOStatement */
    private $query;

    /** @var  callable */
    private $hasher;

    /** @var  string */
    private $userId;

    /**
     * Needs a prepared query that should look like this:
     *     SELECT id FROM users WHERE username = :username AND password = :password
     *
     * @param  \PDOStatement $query
     * @param  callable $hasher hashes the password before checking it against the database
     */
    public function __construct(\PDOStatement $query, callable $hasher)
    {
        $this->query = $query;
        $this->hasher = $hasher;
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
    private function getEventDispatcher()
    {
        return $this->eventDispatcher;
    }

    /** @return  \PDOStatement */
    private function getQuery()
    {
        return $this->query;
    }

    /**
     * Uses the provided hasher to hash the password
     *
     * @param   string $password
     * @return  string
     */
    private function hash($password)
    {
        return call_user_func($this->hasher, $password);
    }

    /**
     * Sees if there's a user to authenticate
     *
     * @param   ValidationEvent $event
     * @return  void
     */
    public function validateVisitor(ValidationEvent $event)
    {
        $request = $event->getRequest();

        $authenticationEvent = new AuthenticationEvent($request);
        $this->getEventDispatcher()->dispatch(Firewall::EVENT_AUTHENTICATE, $authenticationEvent);

        if ($authenticationEvent->isAuthenticated()) {
            $user = $authenticationEvent->getUser();
            $this->userId = $user['id'];
        } else {
            $event->setState(ValidationEvent::STATE_REFUSED);
            $event->setMessage('Authentication failed');
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
        if (!$username || !$password) {
            return;
        }

        $query = $this->getQuery();
        $query->execute(
            [
                'username' => $username,
                'password' => $this->hash($password),
            ]
        );
        if ($query->rowCount() > 0) {
            $user = $query->fetch(\PDO::FETCH_ASSOC);
            $event->setUser($user);
        }
    }

    public function addUserToToken(CreateTokenEvent $event)
    {
        // @todo add the userId to the token
    }
}
