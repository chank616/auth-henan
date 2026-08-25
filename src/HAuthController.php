<?php

namespace Blessing\HAuth;

use App\Events;
use App\Models\Player;
use App\Models\User;
use App\Rules;
use Auth;
use Blessing\Filter;
use Blessing\HAuth\Utils\MfaCapableSchoolAuth;
use Blessing\HAuth\Utils\MfaRequiredException;
use Blessing\Rejection;
use Carbon\Carbon;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Vectorface\Whip\Whip;

class HAuthController
{
    private const MFA_SESSION_PREFIX = 'henan_auth.mfa.';
    private const MFA_LIFETIME = 300;
    private const MFA_RESEND_INTERVAL = 60;

    public function login(Filter $filter, string $msg = '', array $userData = [])
    {
        return view('Blessing\HAuth::auth.login', [
            'rows' => [
                'Blessing\HAuth::auth.rows.login.notice',
                'Blessing\HAuth::auth.rows.login.form',
                'Blessing\HAuth::auth.rows.login.message',
            ],
            'schools' => SchoolRegistry::names(),
            'msg' => $msg,
            'user_data' => $userData,
        ]);
    }

    public function register(Filter $filter, string $msg = '', array $userData = [])
    {
        return view('Blessing\HAuth::auth.register', [
            'rows' => [
                'Blessing\HAuth::auth.rows.register.notice',
                'Blessing\HAuth::auth.rows.register.form',
            ],
            'schools' => SchoolRegistry::names(),
            'extra' => [
                'recaptcha' => option('recaptcha_sitekey'),
                'invisible' => (bool) option('recaptcha_invisible'),
            ],
            'msg' => $msg,
            'user_data' => $userData,
        ]);
    }

    public function mfa(Request $request, string $token)
    {
        $pending = $this->pendingMfa($request, $token);
        if ($pending === null) {
            return redirect(url('/auth/login/henan'))->with(
                'msg',
                trans('Blessing\HAuth::auth.mfa.expired')
            );
        }

        return view('Blessing\HAuth::auth.mfa', [
            'token' => $token,
            'destination' => $pending['destination'],
            'operation' => $pending['operation'],
            'sent' => !empty($pending['sent_at']),
            'msg' => (string) $request->session()->pull('henan_mfa_message', ''),
        ]);
    }

    public function sendMfaCode(Request $request, string $token)
    {
        $pending = $this->pendingMfa($request, $token);
        if ($pending === null) {
            return $this->expiredMfaRedirect();
        }

        $remaining = self::MFA_RESEND_INTERVAL - (time() - (int) $pending['sent_at']);
        if ($remaining > 0) {
            return $this->mfaRedirect(
                $token,
                trans('Blessing\HAuth::auth.mfa.cooldown', ['seconds' => $remaining])
            );
        }

        $auth = SchoolRegistry::make($pending['school']);
        if (!$auth instanceof MfaCapableSchoolAuth) {
            return $this->mfaRedirect(
                $token,
                trans('Blessing\HAuth::auth.mfa.unavailable')
            );
        }

        try {
            $pending['challenge'] = $auth->sendMfaCode($pending['challenge']);
        } catch (\Throwable $exception) {
            return $this->mfaRedirect(
                $token,
                trans('Blessing\HAuth::auth.mfa.send-failed')
            );
        }

        $pending['sent_at'] = time();
        $request->session()->put($this->mfaSessionKey($token), $pending);

        return $this->mfaRedirect($token, trans('Blessing\HAuth::auth.mfa.sent'));
    }

    public function verifyMfa(
        Request $request,
        Dispatcher $dispatcher,
        Filter $filter,
        string $token
    ) {
        $data = $request->validate([
            'code' => 'required|string|regex:/^[0-9]{4,8}$/',
        ]);
        $pending = $this->pendingMfa($request, $token);
        if ($pending === null) {
            return $this->expiredMfaRedirect();
        }
        if (empty($pending['sent_at'])) {
            return $this->mfaRedirect($token, trans('Blessing\HAuth::auth.mfa.send-first'));
        }

        $auth = SchoolRegistry::make($pending['school']);
        if (!$auth instanceof MfaCapableSchoolAuth) {
            return $this->mfaRedirect(
                $token,
                trans('Blessing\HAuth::auth.mfa.unavailable')
            );
        }

        try {
            $context = $auth->verifyMfaCode($pending['challenge'], $data['code']);
            if ($context === null) {
                return $this->mfaRedirect($token, trans('Blessing\HAuth::auth.mfa.invalid-code'));
            }

            if (!$auth->completeMfaLogin($pending['identification'], $context)) {
                $request->session()->forget($this->mfaSessionKey($token));

                return $this->authenticationFailure(
                    $filter,
                    $pending,
                    trans('Blessing\HAuth::auth.validation.credentials')
                );
            }
        } catch (\Throwable $exception) {
            return $this->mfaRedirect($token, trans('Blessing\HAuth::auth.mfa.unavailable'));
        }

        $request->session()->forget($this->mfaSessionKey($token));

        if ($pending['operation'] === 'register') {
            return $this->finishRegister($request, $dispatcher, $filter, $pending);
        }

        return $this->finishLogin($request, $dispatcher, $filter, $pending);
    }

    public function cancelMfa(Request $request, string $token)
    {
        $pending = $this->pendingMfa($request, $token);
        $request->session()->forget($this->mfaSessionKey($token));

        if ($pending !== null && $pending['operation'] === 'register') {
            return redirect(url('/auth/register/henan'));
        }

        return redirect(url('/auth/login/henan'));
    }

    public function handleLogin(
        Request $request,
        Dispatcher $dispatcher,
        Filter $filter
    ) {
        $data = $request->validate([
            'school' => 'required|in:' . implode(',', array_keys(SchoolRegistry::SCHOOLS)),
            'identification' => 'required|string|max:255',
            'password' => 'required|string',
        ]);
        $userData = $request->only(['school', 'identification']);
        $email = $data['identification'] . SchoolRegistry::emailDomain($data['school']);

        $can = $filter->apply('can_login', null, [$email, $data['password']]);
        if ($can instanceof Rejection) {
            return $this->login($filter, $can->getReason(), $userData);
        }

        $dispatcher->dispatch('auth.login.attempt', [$email, $data['password'], 'email']);
        event(new Events\UserTryToLogin($email, 'email'));

        if (!User::where('email', $email)->exists()) {
            return $this->login(
                $filter,
                trans('Blessing\HAuth::auth.validation.unregistered'),
                $userData
            );
        }

        try {
            $authenticated = SchoolRegistry::login(
                $data['school'],
                $data['identification'],
                $data['password']
            );
        } catch (MfaRequiredException $challenge) {
            return $this->beginMfa($request, 'login', [
                'school' => $data['school'],
                'identification' => $data['identification'],
            ], $challenge);
        } catch (\Throwable $exception) {
            return $this->login(
                $filter,
                trans('Blessing\HAuth::auth.validation.unavailable'),
                $userData
            );
        }

        if (!$authenticated) {
            return $this->login(
                $filter,
                trans('Blessing\HAuth::auth.validation.credentials'),
                $userData
            );
        }

        return $this->finishLogin($request, $dispatcher, $filter, $data);
    }

    public function handleRegister(
        Request $request,
        Rules\Captcha $captcha,
        Dispatcher $dispatcher,
        Filter $filter
    ) {
        $can = $filter->apply('can_register', null);
        if ($can instanceof Rejection) {
            return $this->register($filter, $can->getReason());
        }

        $data = $request->validate([
            'school' => 'required|in:' . implode(',', array_keys(SchoolRegistry::SCHOOLS)),
            'identification' => 'required|string|max:255',
            'password' => 'required|string',
            'site_password' => 'required|string|min:8|max:32',
            'player_name' => [
                'required',
                new Rules\PlayerName(),
                'min:' . option('player_name_length_min'),
                'max:' . option('player_name_length_max'),
            ],
            'captcha' => ['required', $captcha],
        ]);
        $userData = $request->only(['school', 'identification', 'player_name']);

        try {
            $authenticated = SchoolRegistry::login(
                $data['school'],
                $data['identification'],
                $data['password']
            );
        } catch (MfaRequiredException $challenge) {
            return $this->beginMfa($request, 'register', [
                'school' => $data['school'],
                'identification' => $data['identification'],
                'player_name' => $data['player_name'],
                'password_hash' => $this->hashLocalPassword($data['site_password'], $filter),
            ], $challenge);
        } catch (\Throwable $exception) {
            return $this->register(
                $filter,
                trans('Blessing\HAuth::auth.validation.unavailable'),
                $userData
            );
        }

        if (!$authenticated) {
            return $this->register(
                $filter,
                trans('Blessing\HAuth::auth.validation.credentials'),
                $userData
            );
        }

        $data['password_hash'] = $this->hashLocalPassword($data['site_password'], $filter);

        return $this->finishRegister($request, $dispatcher, $filter, $data);
    }

    private function finishLogin(
        Request $request,
        Dispatcher $dispatcher,
        Filter $filter,
        array $data
    ) {
        $email = $data['identification'] . SchoolRegistry::emailDomain($data['school']);
        $user = User::where('email', $email)->first();
        if (!$user) {
            return $this->login(
                $filter,
                trans('Blessing\HAuth::auth.validation.unregistered'),
                $data
            );
        }

        $dispatcher->dispatch('auth.login.ready', [$user]);

        if (!$user->verified) {
            $user->verified = true;
            $user->save();
        }

        Auth::login($user);

        $dispatcher->dispatch('auth.login.succeeded', [$user]);
        event(new Events\UserLoggedIn($user));

        return redirect($request->session()->pull('last_requested_path', url('/user')));
    }

    private function finishRegister(
        Request $request,
        Dispatcher $dispatcher,
        Filter $filter,
        array $data
    ) {
        $email = $data['identification'] . SchoolRegistry::emailDomain($data['school']);
        $userData = [
            'school' => $data['school'],
            'identification' => $data['identification'],
            'player_name' => $data['player_name'],
        ];

        if (User::where('email', $email)->exists()) {
            return $this->register(
                $filter,
                trans('Blessing\HAuth::auth.validation.registered'),
                $userData
            );
        }

        if (Player::where('name', $data['player_name'])->exists()) {
            return $this->register($filter, trans('user.player.add.repeated'), $userData);
        }

        $whip = new Whip();
        $ip = $filter->apply('client_ip', $whip->getValidIpAddress());
        if (User::where('ip', $ip)->count() >= option('regs_per_ip')) {
            return $this->register(
                $filter,
                trans('auth.register.max', ['regs' => option('regs_per_ip')]),
                $userData
            );
        }

        $registrationData = [
            'email' => $email,
            'nickname' => $data['player_name'],
            'player_name' => $data['player_name'],
        ];
        $dispatcher->dispatch('auth.registration.attempt', [$registrationData]);
        $dispatcher->dispatch('auth.registration.ready', [$registrationData]);

        $user = new User();
        $user->email = $email;
        $user->nickname = $data['player_name'];
        $user->score = option('user_initial_score');
        $user->avatar = 0;
        $user->password = $data['password_hash'];
        $user->ip = $ip;
        $user->permission = User::NORMAL;
        $user->verified = true;
        $user->register_at = Carbon::now();
        $user->last_sign_at = Carbon::now()->subDay();
        $user->save();

        $dispatcher->dispatch('auth.registration.completed', [$user]);
        event(new Events\UserRegistered($user));

        $dispatcher->dispatch('player.adding', [$data['player_name'], $user]);

        $player = new Player();
        $player->uid = $user->uid;
        $player->name = $data['player_name'];
        $player->tid_skin = 0;
        $player->save();

        $dispatcher->dispatch('player.added', [$player, $user]);
        event(new Events\PlayerWasAdded($player));

        $dispatcher->dispatch('auth.login.ready', [$user]);
        Auth::login($user);
        $dispatcher->dispatch('auth.login.succeeded', [$user]);
        event(new Events\UserLoggedIn($user));

        return redirect(url('/user'));
    }

    private function beginMfa(
        Request $request,
        string $operation,
        array $data,
        MfaRequiredException $challenge
    ) {
        $token = bin2hex(random_bytes(32));
        $pending = array_merge($data, [
            'operation' => $operation,
            'destination' => $challenge->destination(),
            'challenge' => $challenge->context(),
            'expires_at' => time() + self::MFA_LIFETIME,
            'sent_at' => 0,
        ]);
        $request->session()->put($this->mfaSessionKey($token), $pending);

        return redirect(url('/auth/mfa/henan/' . $token));
    }

    private function pendingMfa(Request $request, string $token): ?array
    {
        if (preg_match('/^[a-f0-9]{64}$/', $token) !== 1) {
            return null;
        }

        $key = $this->mfaSessionKey($token);
        $pending = $request->session()->get($key);
        if (!is_array($pending) || (int) ($pending['expires_at'] ?? 0) < time()) {
            $request->session()->forget($key);

            return null;
        }

        foreach (['operation', 'school', 'identification', 'destination', 'challenge'] as $field) {
            if (!array_key_exists($field, $pending)) {
                $request->session()->forget($key);

                return null;
            }
        }

        return $pending;
    }

    private function authenticationFailure(Filter $filter, array $pending, string $message)
    {
        $userData = [
            'school' => $pending['school'],
            'identification' => $pending['identification'],
            'player_name' => $pending['player_name'] ?? '',
        ];

        if ($pending['operation'] === 'register') {
            return $this->register($filter, $message, $userData);
        }

        return $this->login($filter, $message, $userData);
    }

    private function mfaRedirect(string $token, string $message)
    {
        return redirect(url('/auth/mfa/henan/' . $token))
            ->with('henan_mfa_message', $message);
    }

    private function expiredMfaRedirect()
    {
        return redirect(url('/auth/login/henan'))
            ->with('msg', trans('Blessing\HAuth::auth.mfa.expired'));
    }

    private function mfaSessionKey(string $token): string
    {
        return self::MFA_SESSION_PREFIX . $token;
    }

    private function hashLocalPassword(string $password, Filter $filter): string
    {
        $hash = app('cipher')->hash($password, config('secure.salt'));

        return $filter->apply('user_password', $hash);
    }
}
