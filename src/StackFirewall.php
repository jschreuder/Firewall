<?php

namespace Webspot\Firewall;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class StackFirewall implements HttpKernelInterface
{
    /** @var  HttpKernelInterface */
    private $app;

    /** @var  Firewall */
    private $firewall;

    public function __construct(HttpKernelInterface $app, Firewall $firewall)
    {
        $this->app = $app;
        $this->firewall = $firewall;
    }

    /** {@inheritdoc} */
    public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = true)
    {
        try {
            $this->firewall->guard($request);
            $response = $this->app->handle($request, $type, $catch);
            $this->firewall->signOff($response);
            return $response;
        } catch (\Exception $e) {
            if (!$catch) {
                throw $e;
            }

            return new Response('['.get_class($e).'] '.$e->getMessage(), $e->getCode() ?: 403);
        }
    }
}
