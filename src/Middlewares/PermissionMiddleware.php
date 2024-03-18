<?php

namespace Dadansatria\Permission\Middlewares;

use Closure;
use Dadansatria\Permission\Exceptions\UnauthorizedException;
use Dadansatria\Permission\Exceptions\UnauthorizedPermission;
use Dadansatria\Permission\Exceptions\UserNotLoggedIn;
use Dadansatria\Permission\Helpers;
use function explode;
use function is_array;

/**
 * Class PermissionMiddleware
 * @package Dadansatria\Permission\Middlewares
 */
class PermissionMiddleware
{
    /**
     * @param $request
     * @param Closure $next
     * @param $permission
     *
     * @return mixed
     * @throws UnauthorizedException
     */
    public function handle($request, Closure $next, $permission): mixed
    {
        if (app('auth')->guest()) {
            $helpers = new Helpers();
            throw new UserNotLoggedIn(403, $helpers->getUserNotLoggedINMessage());
        }

        $permissions = is_array($permission) ? $permission : explode('|', $permission);


        if (! app('auth')->user()->hasAnyPermission($permissions)) {
            $helpers = new Helpers();
            throw new UnauthorizedPermission(
                403,
                $helpers->getUnauthorizedPermissionMessage(implode(', ', $permissions)),
                $permissions
            );
        }

        return $next($request);
    }
}
