<?php

namespace Webspot\Firewall\Test;

use PHPUnit_Framework_TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Webspot\Application\Application;
use Webspot\Firewall\Exception\FirewallException;
use Webspot\Firewall\StackFirewall;

class StackFirewallTest extends PHPUnit_Framework_TestCase
{
    /** @var  StackFirewall */
    private $stackFirewall;

    /** @var  \Symfony\Component\HttpKernel\HttpKernelInterface | \PHPUnit_Framework_MockObject_MockObject */
    private $app;

    /** @var  \Webspot\Firewall\Firewall | \PHPUnit_Framework_MockObject_MockObject */
    private $firewall;

    public function setUp()
    {
        $this->app = $this->getMockForAbstractClass('Symfony\Component\HttpKernel\HttpKernelInterface');
        $this->firewall = $this->getMock('Webspot\Firewall\Firewall');
        $this->stackFirewall = new StackFirewall($this->app, $this->firewall);
    }

    public function testHandle()
    {
        $request = new Request();
        $response = new Response();

        $this->firewall->expects($this->once())
            ->method('guard')
            ->with($this->equalTo($request));

        $this->app->expects($this->once())
            ->method('handle')
            ->with($this->equalTo($request))
            ->will($this->returnValue($response));

        $this->firewall->expects($this->once())
            ->method('sendResponse')
            ->with($this->equalTo($response));

        $this->assertSame($response, $this->stackFirewall->handle($request));
    }

    /**
     * @expectedException  \Webspot\Firewall\Exception\FirewallException
     */
    public function testHandleHandleException()
    {
        $request = new Request();

        $this->firewall->expects($this->exactly(2))
            ->method('guard')
            ->with($this->equalTo($request))
            ->will($this->throwException(new FirewallException($message = 'Your request was bad', $code = 400)));

        $this->app->expects($this->never())
            ->method('handle');

        $response = $this->stackFirewall->handle($request);
        $this->assertContains($message, $response->getContent());
        $this->assertEquals($code, $response->getStatusCode());

        $this->stackFirewall->handle($request, Application::MASTER_REQUEST, false);
    }

    /**
     * @expectedException  \Webspot\Firewall\Exception\FirewallException
     */
    public function testHandleSendResponseException()
    {
        $request = new Request();
        $response = new Response();

        $this->firewall->expects($this->exactly(2))
            ->method('guard')
            ->with($this->equalTo($request));

        $this->app->expects($this->exactly(2))
            ->method('handle')
            ->with($this->equalTo($request))
            ->will($this->returnValue($response));

        $this->firewall->expects($this->exactly(2))
            ->method('sendResponse')
            ->with($this->equalTo($response))
            ->will($this->throwException(new FirewallException($message = 'Your request was bad', $code = 400)));

        $response = $this->stackFirewall->handle($request);
        $this->assertContains($message, $response->getContent());
        $this->assertEquals($code, $response->getStatusCode());

        $this->stackFirewall->handle($request, Application::MASTER_REQUEST, false);
    }
}
