<?php

use Blessing\Filter;
use Blessing\Rejection;

use Illuminate\Contracts\Events\Dispatcher;

use App\Services\Hook;

use Blessing\HAuth\HAuthController;

return function (Dispatcher $events, Filter $filter) {
    $appendEntry = static function (array $rows, string $entry) {
        $rows = array_values(array_filter($rows, static function ($row) use ($entry) {
            return $row !== $entry;
        }));
        $rows[] = $entry;

        return $rows;
    };

    $filter->add('auth_page_rows:login', static function (array $rows) use ($appendEntry) {
        return $appendEntry($rows, 'Blessing\\HAuth::auth.entry');
    }, 100);
    $filter->add('auth_page_rows:register', static function (array $rows) use ($appendEntry) {
        return $appendEntry($rows, 'Blessing\\HAuth::auth.register-entry');
    }, 100);

    $filter->add('grid:user.profile', static function (array $grid) {
        $removeEmailWidget = static function (array $items) use (&$removeEmailWidget) {
            foreach ($items as $key => $item) {
                if ($item === 'user.widgets.profile.email') {
                    unset($items[$key]);
                } elseif (is_array($item)) {
                    $items[$key] = $removeEmailWidget($item);
                }
            }

            return array_values($items);
        };

        $grid['widgets'] = $removeEmailWidget($grid['widgets'] ?? []);

        return $grid;
    }, 100);

    $filter->add('user_can_edit_profile', static function ($can, string $action) {
        if ($action === 'email') {
            return new Rejection(trans('Blessing\\HAuth::auth.validation.email-locked'));
        }

        return $can;
    }, 100);

    Hook::addRoute(function () {
        Route::prefix('auth')
            ->namespace('Blessing\HAuth')
            ->middleware(['web', 'guest'])
            ->group(function () {
                Route::get('login/henan', [HAuthController::class, 'login']);
                Route::post('login/henan', [HAuthController::class, 'handleLogin']);
                Route::get('register/henan', [HAuthController::class, 'register']);
                Route::post('register/henan', [HAuthController::class, 'handleRegister']);
                Route::get('mfa/henan/{token}', [HAuthController::class, 'mfa'])
                    ->where('token', '[a-f0-9]{64}');
                Route::post('mfa/henan/{token}/send', [HAuthController::class, 'sendMfaCode'])
                    ->where('token', '[a-f0-9]{64}');
                Route::post('mfa/henan/{token}/verify', [HAuthController::class, 'verifyMfa'])
                    ->where('token', '[a-f0-9]{64}');
                Route::post('mfa/henan/{token}/cancel', [HAuthController::class, 'cancelMfa'])
                    ->where('token', '[a-f0-9]{64}');
            });
    });
};
