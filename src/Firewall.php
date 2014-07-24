<?php

namespace Webspot\Firewall;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Webspot\Firewall\Event\AllowedEvent;
use Webspot\Firewall\Event\RefusedEvent;
use Webspot\Firewall\Event\ValidationEvent;

class Firewall
{
    // Normal execution consists of these 3 events: the actual validation, allowed and refused
    const EVENT_VALIDATE_VISITOR = 'validate';
    const EVENT_VISITOR_ALLOWED = 'allowed';
    const EVENT_VISITOR_REFUSED = 'refused';

    // When the visitor is allowed this may be stored in a token to save resources on subsequent requests
    const EVENT_CREATE_TOKEN = 'create-token';

    // These events are triggered and dealt with during EVENT_VALIDATE_VISITOR
    const EVENT_VALIDATE_TOKEN = 'validate-token';
    const EVENT_TOKEN_VALIDATED = 'token-validated';

    // When authenticating a user
    const EVENT_AUTHENTICATE = 'authenticate';

    /** @var  EventDispatcher */
    private $eventDispatcher;

    public function __construct()
    {
        $this->eventDispatcher = new EventDispatcher();
    }

    /** @return  EventDispatcher */
    private function getEventDispatcher()
    {
        return $this->eventDispatcher;
    }

    /**
     * @param   FirewallSubscriberInterface $subscriber
     * @return  self
     */
    public function attachSubscriber(FirewallSubscriberInterface $subscriber)
    {
        $this->getEventDispatcher()->addSubscriber($subscriber);
        $subscriber->setEventDispatcher($this->getEventDispatcher());
        return $this;
    }

    /**
     * @param   Request $request
     * @return  void
     * @throws  \Exception when validation fails
     */
    public function validate(Request $request)
    {
        $validationEvent = new ValidationEvent($request);

        try {
            $this->getEventDispatcher()->dispatch(self::EVENT_VALIDATE_VISITOR, $validationEvent);
        } catch (\Exception $e) {
            $validationEvent->setState(ValidationEvent::STATE_REFUSED);
            $validationEvent->setMessage('An error occurred: '.$e->getMessage());
        }

        if ( ! $validationEvent->isAllowed()) {
            $refusedEvent = new RefusedEvent($request, $validationEvent->getMessage());
            $this->getEventDispatcher()->dispatch(self::EVENT_VISITOR_REFUSED, $refusedEvent);
            throw new FirewallException($refusedEvent->getMessage(), isset($e) ? $e : null);
        }

        $allowedEvent = new AllowedEvent($request, $validationEvent->getMessage());
        $this->getEventDispatcher()->dispatch(self::EVENT_VISITOR_ALLOWED, $allowedEvent);
    }
}
