<?php

namespace Webspot\Firewall\Test\Guard;

use PHPUnit_Framework_TestCase;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Guard\IpGuard;

class IpGuardTest extends PHPUnit_Framework_TestCase
{
    /** @var  ValidationEvent | \PHPUnit_Framework_MockObject_MockObject */
    private $event;

    public function setUp()
    {
        $this->event = $this->getMockBuilder('Webspot\Firewall\Event\ValidationEvent')
            ->disableOriginalConstructor()->getMock();
    }

    public function testValidateRequestIpUnknown()
    {
        $ipAddress = '0.0.0.1';

        $checker = function ($ip) use ($ipAddress) {
            $this->assertEquals($ipAddress, $ip);
            return IpGuard::STATUS_UNKNOWN;
        };
        $ipGuard = new IpGuard($checker);

        /** @var  \Symfony\Component\HttpFoundation\Request | \PHPUnit_Framework_MockObject_MockObject $request */
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $request->expects($this->once())
            ->method('getClientIp')
            ->will($this->returnValue($ipAddress));

        $this->event->expects($this->once())
            ->method('getRequest')
            ->will($this->returnValue($request));

        $ipGuard->validateRequest($this->event);
    }

    public function testValidateRequestBadIp()
    {
        $ipAddress = 'abc.def.ghi.jkl';

        $checker = function ($ip) use ($ipAddress) {
            throw new \Exception('This should not happen.');
        };
        $ipGuard = new IpGuard($checker);

        /** @var  \Symfony\Component\HttpFoundation\Request | \PHPUnit_Framework_MockObject_MockObject $request */
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $request->expects($this->once())
            ->method('getClientIp')
            ->will($this->returnValue($ipAddress));

        $this->event->expects($this->once())
            ->method('getRequest')
            ->will($this->returnValue($request));

        $this->event->expects($this->once())
            ->method('setState')
            ->with($this->equalTo(ValidationEvent::STATE_REFUSED));
        $this->event->expects($this->once())
            ->method('setMessage')
            ->with($this->isType('string'));
        $this->event->expects($this->once())
            ->method('setException')
            ->with($this->isInstanceOf('Webspot\Firewall\Exception\ForbiddenException'));

        $ipGuard->validateRequest($this->event);
    }

    public function testValidateRequestBlacklistedIp()
    {
        $ipAddress = '1.1.1.2';

        $checker = function ($ip) use ($ipAddress) {
            $this->assertEquals($ipAddress, $ip);
            return IpGuard::STATUS_BLACKLIST;
        };
        $ipGuard = new IpGuard($checker);

        /** @var  \Symfony\Component\HttpFoundation\Request | \PHPUnit_Framework_MockObject_MockObject $request */
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $request->expects($this->once())
            ->method('getClientIp')
            ->will($this->returnValue($ipAddress));

        $this->event->expects($this->once())
            ->method('getRequest')
            ->will($this->returnValue($request));

        $this->event->expects($this->once())
            ->method('setState')
            ->with($this->equalTo(ValidationEvent::STATE_REFUSED));
        $this->event->expects($this->once())
            ->method('setMessage')
            ->with($this->isType('string'));
        $this->event->expects($this->once())
            ->method('setException')
            ->with($this->isInstanceOf('Webspot\Firewall\Exception\ForbiddenException'));

        $ipGuard->validateRequest($this->event);
    }

    public function testValidateRequestWhitelistedIp()
    {
        $ipAddress = '1.1.1.3';

        $checker = function ($ip) use ($ipAddress) {
            $this->assertEquals($ipAddress, $ip);
            return IpGuard::STATUS_WHITELIST;
        };
        $ipGuard = new IpGuard($checker);

        /** @var  \Symfony\Component\HttpFoundation\Request | \PHPUnit_Framework_MockObject_MockObject $request */
        $request = $this->getMock('Symfony\Component\HttpFoundation\Request');
        $request->expects($this->once())
            ->method('getClientIp')
            ->will($this->returnValue($ipAddress));

        $this->event->expects($this->once())
            ->method('getRequest')
            ->will($this->returnValue($request));

        $this->event->expects($this->once())
            ->method('setState')
            ->with($this->equalTo(ValidationEvent::STATE_ALLOWED));
        $this->event->expects($this->once())
            ->method('setMessage')
            ->with($this->isType('string'));

        $ipGuard->validateRequest($this->event);
    }
}
