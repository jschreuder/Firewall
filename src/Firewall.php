<?php

namespace Webspot\Firewall;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webspot\Firewall\Event\AllowedEvent;
use Webspot\Firewall\Event\RefusedEvent;
use Webspot\Firewall\Event\ResponseEvent;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Exception\FirewallException;
use Webspot\Firewall\Guard\EventDispatcherAwareGuardInterface;
use Webspot\Firewall\Guard\GuardInterface;

class Firewall
{
    // Normal execution consists of these 4 events:
    //     the actual validation, allowed and refused and signing off on the eventual response
    const EVENT_VALIDATE_REQUEST = 'validate';
    const EVENT_REQUEST_ALLOWED = 'allowed';
    const EVENT_REQUEST_REFUSED = 'refused';
    const EVENT_SEND_RESPONSE = 'respond';

    // When the request is allowed this may be stored in a token to save resources on subsequent requests
    const EVENT_CREATE_TOKEN = 'create-token';

    // These events are triggered and dealt with during EVENT_VALIDATE_REQUEST
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
     * @param   GuardInterface $subscriber
     * @return  self
     */
    public function attachGuard(GuardInterface $subscriber)
    {
        $this->getEventDispatcher()->addSubscriber($subscriber);
        if ($subscriber instanceof EventDispatcherAwareGuardInterface) {
            $subscriber->setEventDispatcher($this->getEventDispatcher());
        }
        return $this;
    }

    /**
     * @param   Request $request
     * @return  void
     * @throws  FirewallException when validation fails
     */
    public function guard(Request $request)
    {
        $eventDispatcher = $this->getEventDispatcher();
        $validationEvent = new ValidationEvent($request);

        // Start by validating the request, any/every exception will lead to automatic refusal
        try {
            $eventDispatcher->dispatch(self::EVENT_VALIDATE_REQUEST, $validationEvent);
        } catch (\Exception $e) {
            $validationEvent->setState(ValidationEvent::STATE_REFUSED);
            $validationEvent->setMessage('An error occurred: ' . $e->getMessage());
        }

        // When the request ends up refused, trigger that event and throw exception to be handled outside the firewall
        if (!$validationEvent->isAllowed()) {
            $refusedEvent = new RefusedEvent($request, $validationEvent->getMessage());
            $eventDispatcher->dispatch(self::EVENT_REQUEST_REFUSED, $refusedEvent);

            if ($exception = $validationEvent->getException()) {
                throw $exception;
            } else {
                throw new FirewallException($refusedEvent->getMessage());
            }
        }

        $allowedEvent = new AllowedEvent($request);
        $eventDispatcher->dispatch(self::EVENT_REQUEST_ALLOWED, $allowedEvent);
    }

    /**
     * @param   Response $response
     * @return  void
     */
    public function sendResponse(Response $response)
    {
        $signOffEvent = new ResponseEvent($response);
        $this->getEventDispatcher()->dispatch(self::EVENT_SEND_RESPONSE, $signOffEvent);
    }
}
