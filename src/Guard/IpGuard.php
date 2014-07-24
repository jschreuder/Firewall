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

    /** @var  \PDOStatement */
    private $query;

    /**
     * Needs a prepared query that should look like this:
     *     SELECT status FROM ip_addresses WHERE ip = :ip ORDER BY created_at DESC LIMIT 1
     *
     * @param  \PDOStatement $query
     */
    public function __construct(\PDOStatement $query)
    {
        $this->query = $query;
    }

    /**
     * @param   EventDispatcher $eventDispatcher
     * @return  void
     */
    public function setEventDispatcher(EventDispatcher $eventDispatcher)
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    /** @return  \PDOStatement */
    private function getQuery()
    {
        return $this->query;
    }

    /**
     * @param   ValidationEvent $event
     * @return  void
     */
    public function validateRequest(ValidationEvent $event)
    {
        $state = $this->determineIpState($event->getRequest()->getClientIp());
        if ($state === self::STATUS_BLACKLIST) {
            $event->setState(ValidationEvent::STATE_REFUSED);
            $event->setMessage('IP address blacklisted');
            $event->setException(new ForbiddenException());
        } elseif ($state === self::STATUS_WHITELIST) {
            $event->setState(ValidationEvent::STATE_ALLOWED);
            $event->setMessage('IP address whitelisted');
        }
    }

    /**
     * @param   string $ip
     * @return  int  one of the STATUS_* constants
     */
    private function determineIpState($ip)
    {
        // Query if the IP is known
        $query = $this->getQuery();
        $query->execute(['ip' => $ip]);

        // No result means unknown IP
        if ($query->rowCount() === 0) {
            return self::STATUS_UNKNOWN;
        }

        // Otherwise return the row's status
        $row = $this->getQuery()->fetch(\PDO::FETCH_ASSOC);
        return intval($row['status']);
    }
}
