<?php

namespace Webspot\Firewall\Subscriber;

use Psecio\Jwt;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\Request;
use Webspot\Firewall\Event\AllowedEvent;
use Webspot\Firewall\Event\TokenValidatedEvent;
use Webspot\Firewall\Event\TokenValidationEvent;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Firewall;
use Webspot\Firewall\FirewallSubscriberInterface;

class TokenSubscriber implements FirewallSubscriberInterface
{
    /** {@inheritdoc} */
    public static function getSubscribedEvents()
    {
        return [
            Firewall::EVENT_VALIDATE_VISITOR => ['validateVisitor', 1024],
            Firewall::EVENT_VALIDATE_TOKEN => ['validateToken', 0],
            Firewall::EVENT_VISITOR_ALLOWED => ['visitorAllowed', 0],
            Firewall::EVENT_CREATE_TOKEN => ['createToken', 0],
            Firewall::EVENT_CREATE_TOKEN => ['writeCreateToken', -1024],
        ];
    }

    /** @var  string */
    private $key;

    /** @var  string */
    private $cookieName;

    /** @var  EventDispatcher */
    private $eventDispatcher;

    /** @var  int */
    private $expiresIn;

    /**
     * @param  string $key
     * @param  string $cookieName
     * @param  int $expiresIn number of seconds after which the token should expire
     */
    public function __construct($key, $cookieName = 'ws-token', $expiresIn = 7200)
    {
        $this->key = $key;
        $this->cookieName = $cookieName;
        $this->expiresIn = $expiresIn;
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

    /** @return  string */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param   Request $request
     * @return  string
     */
    private function getTokenFromRequest(Request $request)
    {
        return $request->cookies->get($this->cookieName);
    }

    /**
     * @param   ValidationEvent $event
     * @return  void
     */
    public function validateVisitor(ValidationEvent $event)
    {
        $eventDispatcher = $this->getEventDispatcher();
        $request = $event->getRequest();

        // Check for a token, otherwise nothing to do
        $token = $this->getTokenFromRequest($request);
        if (!$token) {
            return;
        }

        // Trigger the token validation
        $tokenValidationEvent = new TokenValidationEvent($token, $request);
        $eventDispatcher->dispatch(Firewall::EVENT_VALIDATE_TOKEN, $tokenValidationEvent);

        // Check the token, when it validates that should immediately allow or it should immediately prevent when
        // it gets a STATE_ILLEGAL back. The STATE_INVALID will do nothing
        if ($tokenValidationEvent->isValid()) {
            $event->setState(ValidationEvent::STATE_ALLOWED);

            // Allow hooks into the validated token by triggering an extra event
            $tokenValidatedEvent = new TokenValidatedEvent($tokenValidationEvent->getToken(), $request);
            $eventDispatcher->dispatch(Firewall::EVENT_TOKEN_VALIDATED, $tokenValidatedEvent);
        } elseif ($tokenValidationEvent->isIllegal()) {
            $event->setState(ValidationEvent::STATE_REFUSED);
        }
    }

    /**
     * Validates the token
     *
     * @param   TokenValidationEvent $event
     * @return  void
     */
    public function validateToken(TokenValidationEvent $event)
    {
        // Decode the token and respond accordingly
        $jwt = new Jwt\Jwt(new Jwt\Header($this->getKey()));
        try {
            $decoded = $jwt->decode($event->getToken());
        } catch (\Exception $e) {
            // @todo add support for detecting a cookie with wrong signage to output as STATE_ILLEGAL?
            return;
        }

        // When the token was decoded and the firewall pass is set, allow through:
        if ($decoded->firewall_pass === true) {
            $event->setState(TokenValidationEvent::STATE_VALIDATED);
        }
    }

    public function visitorAllowed(AllowedEvent $event)
    {
        // @todo check if token needs to be created and dispatch EVENT_CREATE_TOKEN when it does
    }

    public function createToken(CreateTokenEvent $event)
    {
        // @todo create a Jwt\Jwt object and assign it to the event
    }

    public function writeCreatedToken(CreateTokenEvent $event)
    {
        // @todo this should be executed last and writes the encoded Jwt\Jwt object to a cookie
    }
}
