<?php

namespace Webspot\Firewall\Test\Guard;

use PHPUnit_Framework_TestCase;
use Symfony\Component\HttpFoundation\Request;
use Webspot\Firewall\Event\ValidationEvent;
use Webspot\Firewall\Firewall;
use Webspot\Firewall\Guard\AuthenticationGuard;

class AuthenticationGuardTest extends PHPUnit_Framework_TestCase
{
    /** @var  ValidationEvent | \PHPUnit_Framework_MockObject_MockObject */
    private $event;

    public function setUp()
    {
        $this->event = $this->getMockBuilder('Webspot\Firewall\Event\ValidationEvent')
            ->disableOriginalConstructor()->getMock();
    }

    public function testSetGetEventDispatcher()
    {
        /** @var  \Symfony\Component\EventDispatcher\EventDispatcher | \PHPUnit_Framework_MockObject_MockObject $ed */
        $ed = $this->getMock('Symfony\Component\EventDispatcher\EventDispatcher');

        $guard = new AuthenticationGuard(function () {
        });
        $guard->setEventDispatcher($ed);

        $method = new \ReflectionMethod($guard, 'getEventDispatcher');
        $method->setAccessible(true);
        $this->assertSame($ed, $method->invoke($guard));
    }

    public function testValidateRequest()
    {
        /** @var  \Symfony\Component\EventDispatcher\EventDispatcher | \PHPUnit_Framework_MockObject_MockObject $ed */
        $ed = $this->getMock('Symfony\Component\EventDispatcher\EventDispatcher');
        $ed->expects($this->once())
            ->method('dispatch')
            ->with(
                $this->equalTo(Firewall::EVENT_AUTHENTICATE),
                $this->isInstanceOf('Webspot\Firewall\Event\AuthenticationEvent')
            );

        $guard = new AuthenticationGuard(function () {
        });
        $guard->setEventDispatcher($ed);

        $this->event->expects($this->once())
            ->method('getRequest')
            ->will($this->returnValue(new Request()));

        $this->event->expects($this->once())
            ->method('setState')
            ->with($this->equalTo(ValidationEvent::STATE_REFUSED));
        $this->event->expects($this->once())
            ->method('setMessage')
            ->with($this->isType('string'));
        $this->event->expects($this->once())
            ->method('setException')
            ->with($this->isInstanceOf('Webspot\Firewall\Exception\UnauthorizedException'));

        $guard->validateRequest($this->event);
    }

    public function testAuthenticateUser()
    {
        /** @var  \Webspot\Firewall\Event\AuthenticationEvent | \PHPUnit_Framework_MockObject_MockObject $ed */
        $event = $this->getMockBuilder('Webspot\Firewall\Event\AuthenticationEvent')
            ->disableOriginalConstructor()->getMock();

        $username = 'han@solo.com';
        $password = 'chewbacca';
        $_1st = 1;

        $event->expects($this->once())
            ->method('getUsername')
            ->will($this->returnValue($username));
        $event->expects($this->once())
            ->method('getPassword')
            ->will($this->returnValue($password));

        $authenticator = function ($user, $pass) use ($username, $password, $_1st) {
            $this->assertEquals($username, $user);
            $this->assertEquals($password, $pass);
            // Han shot...
            return $_1st;
        };

        $event->expects($this->once())
            ->method('setUserId')
            ->with($this->equalTo($_1st));

        $guard = new AuthenticationGuard($authenticator);
        $guard->authenticateUser($event);
    }
}
