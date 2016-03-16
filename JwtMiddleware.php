<?php

namespace go1\jwt_middleware;

use Firebase\JWT\JWT;
use Silex\Api\BootableProviderInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class JwtMiddleware implements BootableProviderInterface
{
    public function boot(Application $app)
    {
        $app->before(function (Request $request) {
            $auth = $request->headers->get('Authorization') ?: $request->headers->get('authorization');
            if ($auth) {
                if (0 === strpos($auth, 'Bearer ')) {
                    $token = substr($auth, 7);
                }
            }

            $token = $request->query->get('jwt', isset($token) ? $token : null);
            if ($token && (2 === substr_count($token, '.'))) {
                $token = explode('.', $token);
                $request->request->set(
                    'jwt.payload',
                    JWT::jsonDecode(JWT::urlsafeB64Decode($token[1]))
                );
            }
        });
    }
}
