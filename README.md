Webspot Firewall
================

#### NOTE: this is pre-alpha, DO NOT USE.

The Firewall is a StackPHP middleware that may be used to check certain guards against unwanted requests. By putting
the Firewall in between your application and the outside world. This is done by attaching Guards to the Firewall that
respond to the internal events and either allow or disallow a request.

When instantiating the Firewall you may choose whether the default state is ALLOWED or REFUSED. The different guards
may change the current state. But while a change to ALLOWED will just continue the verification, when changing to
REFUSED this will immediately become the end-state and no further Guards are checked.

The Events
----------

All events have accompanying Event objects that are specific to their needs.

#### There are 4 main events on the firewall

* `Firewall::EVENT_VALIDATE_REQUEST`

The main-main event. Check if the incoming Request is allowed or not.

* `Firewall::EVENT_REQUEST_ALLOWED`

When the Request validation concluded it's allowed, this event is triggered.

* `Firewall::EVENT_REQUEST_REFUSED`

When the Request validation concluded it's refused, this event is triggered.

* `Firewall::EVENT_SEND_RESPONSE`

After allowed the Request is sent on to the Application, once it gets back with a Response that triggers this Event to
allow signing off on the Response as well.

#### The included guards also trigger a few semi-core events

* `Firewall::EVENT_CREATE_TOKEN`
* `Firewall::EVENT_VALIDATE_TOKEN`
* `Firewall::EVENT_TOKEN_VALIDATED`
* `Firewall::EVENT_AUTHENTICATE`

The Guards
----------

### TokenGuard

Executed the earliest, if a JSON Web Token (JWT) is present and validates all further guarding is dispensed with. Thus
making subsequent requests a lot faster than initial requests. This one also requires the most configuration on
instantiation.

### AuthenticationGuard

For basic HTTP based authentication. Takes a prepared PDOStatement and hash callable to check the username & password
from the HTTP Request headers. When it validates it's `EVENT_AUTHENTICATE` Event object will reflect that. If the
TokenGuard is also attached the user ID is written to the JWT.

### IpGuard

Allows for blacklisting and whitelisting certain IP addresses. Blacklisting will refuse the request when it's IP is
in the database. Whitelisting is only of use when the default state is REFUSED, in which case the whitelisting will
change that state to ALLOWED.

The IpGuard is instantiated with a prepared PDOStatement that allows it to look up the IP and get a state returned.

### UserAgentGuard

Similar to the IpGuard but works on User Agents. This one is not so much a security measure as it is a way to ban
dated browsers or specific devices from using your application.

Upon refusal
------------

Refusal always leads to a FirewallException being thrown. It is recommended to set the handle() method to not catch
Exceptions and catch it yourself in your frontend to deal with. There are three specialised forms of the
FirewallException: ForbiddenException (should lead to HTTP status 403), Unauthorized (status 401) and
UnsupportedException (defaults to 400). Forbidden is thrown by the IpGuard when on the blacklist and the
AuthenticationGuard when it encounters a manipulated JWT. The UnauthorizedException is thrown by the
AuthenticationGuard when there are no credentials or the credentials failed to authenticate. The UnsupportedException
is thrown by the UserAgentGuard.

Note on Exceptions from Guards
------------------------------

Whenever a Guard throws an Exception the Firewall will always default to REFUSED and throw a generic FirewallException
with the actual Exception attached as it's previous property.

Usage example
-------------

```php
<?php
use Psecio\Jwt;
use Webspot\Firewall\Guard;

// Create a StackPHP compatible application, Silex is used here for the example
$app = new Silex\Application();

// Create the Actual Firewall instance and attach some guards
$firewall = new Webspot\Firewall\Firewall();
$firewall->attachGuard(new Guard\AuthenticationGuard(
    function($username, $password) {
        if ($username === 'test@test.com' && $password === 'password') {
            return 42;
        }
        return null;
    }));
$firewall->attachGuard(new Guard\TokenGuard(
        [],
        new Jwt\Jwt(
            new Jwt\Header('my-very-secret-key'),
            (new Jwt\ClaimsCollection())
                ->add(new Jwt\Claim\Audience($_SERVER['SERVER_NAME']))
                ->add(new Jwt\Claim\Issuer($_SERVER['SERVER_NAME']))
                ->add(new Jwt\Claim\ExpireTime(time() + 7200))
                ->add(new Jwt\Claim\Custom(time() + 3600, Guard\TokenGuard::TOKEN_RENEW_AFTER))
        )
    ));

// Create the StackPHP compatible wrapper for the Firewall
$firewalledApp = new Webspot\Firewall\StackFirewall($app, $firewall);

// Return to normal execution
$request = Symfony\Component\HttpFoundation\Request::createFromGlobals();
$respone = $firewalledApp->handle($request);
$response->send();
$app->terminate($request, $response);
```
