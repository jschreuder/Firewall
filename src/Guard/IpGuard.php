<?php

namespace Webspot\Firewall\Guard;

use Symfony\Component\EventDispatcher\EventDispatcher;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Exception\ForbiddenException;
use Webspot\Firewall\Firewall;

class IpGuard implements GuardInterface
{
    const STATUS_BLACKLIST = -1;
    const STATUS_WHITELIST = 1;
    const STATUS_UNKNOWN = 0;

    /** {@inheritdoc} */
    public static function getSubscribedEvents()
    {
        return [
            Firewall::EVENT_VALIDATE_REQUEST => ['validateRequest', 0],
        ];
    }

    /** @var  EventDispatcher */
    private $eventDispatcher;

    /** @var  callable */
    private $ipChecker;

    /**
     * Needs a callable that will accept both an IP and return any of this
     * class's constants as that IP's status. Any value other than 1 or -1
     * is interpreted as 0.
     *
     * @param  callable $ipChecker
     */
    public function __construct(callable $ipChecker)
    {
        $this->ipChecker = $ipChecker;
    }

    /**
     * @param   EventDispatcher $eventDispatcher
     * @return  void
     */
    public function setEventDispatcher(EventDispatcher $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /**
     * @param   string $ip
     * @return  int
     */
    private function checkIp($ip)
    {
        // Invalid IPs always count as blacklisted
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return self::STATUS_BLACKLIST;
        }

        $state = intval(call_user_func($this->ipChecker, $ip));
        if ($state !== self::STATUS_WHITELIST && $state !== self::STATUS_BLACKLIST) {
            $state = self::STATUS_UNKNOWN;
        }
        return $state;
    }

    /**
     * @param   ValidationEvent $event
     * @return  void
     */
    public function validateRequest(ValidationEvent $event)
    {
        $state = $this->checkIp($event->getRequest()->getClientIp());
        if ($state === self::STATUS_BLACKLIST) {
            $event->setState(ValidationEvent::STATE_REFUSED);
            $event->setMessage('IP address blacklisted');
            $event->setException(new ForbiddenException());
        } elseif ($state === self::STATUS_WHITELIST) {
            $event->setState(ValidationEvent::STATE_ALLOWED);
            $event->setMessage('IP address whitelisted');
        }
    }
}
