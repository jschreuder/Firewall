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
        // First guard against intrusion and if there's no problems let's execute the actual request
        // The guard() method will throw an exception if there's a problem
        try {
            $this->firewall->guard($request);
            $response = $this->app->handle($request, $type, $catch);
        } catch (\Exception $e) {
            if (!$catch) {
                throw $e;
            }
            // When we have to catch, throw something mildly readable, though exception should be caught
            // on the outside and handled there accordingly
            $response = new Response('['.get_class($e).'] '.$e->getMessage(), $e->getCode() ?: 403);
        }

        // And try once more, now with the sendResponse() method to sign off if necessary
        try {
            $this->firewall->sendResponse($response);
        } catch (\Exception $e) {
            if (!$catch) {
                throw $e;
            }
            // When we have to catch, throw something mildly readable, though exception should be caught
            // on the outside and handled there accordingly
            $response = new Response('['.get_class($e).'] '.$e->getMessage(), $e->getCode() ?: 403);
        }
        return $response;
    }
}
