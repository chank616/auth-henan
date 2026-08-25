<?php

namespace Blessing\HAuth\Schools;

use Blessing\HAuth\Utils\MfaCapableSchoolAuth;
use Blessing\HAuth\Utils\MfaRequiredException;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Support\Facades\Http;

class ZzuAuth implements MfaCapableSchoolAuth
{
    private const BASE_URL = 'https://cas.s.zzu.edu.cn';
    private const LOGIN_URL = self::BASE_URL . '/cas/a/login';
    private const PUBLIC_KEY_URL = self::BASE_URL . '/cas/jwt/publicKey';
    private const MFA_DETECT_URL = self::BASE_URL . '/cas/mfa/detect';
    private const MFA_INIT_URL = self::BASE_URL . '/cas/mfa/initByType/securephone';
    private const MFA_SERVER_URLS = [
        self::BASE_URL . '/attest',
        self::BASE_URL . '/mf',
    ];

    public function login(string $username, string $password): bool
    {
        $cookieJar = new CookieJar();
        $response = Http::withHeaders($this->headers())
            ->withOptions($this->requestOptions($cookieJar))
            ->get(self::LOGIN_URL);

        if (!$response->successful()) {
            throw new \RuntimeException('无法访问郑州大学统一身份认证登录页');
        }

        $execution = $this->inputValue($response->body(), 'execution');
        if ($execution === null || $execution === '') {
            throw new \RuntimeException('郑州大学统一身份认证登录页缺少会话令牌');
        }

        $encryptedPassword = $this->encryptPassword($password, $cookieJar);
        $mfa = $this->detectMfa($username, $encryptedPassword, $cookieJar);
        $context = [
            'execution' => $execution,
            'encrypted_password' => $encryptedPassword,
            'mfa_state' => $mfa['state'],
            'cookies' => $this->cookieValues($cookieJar),
        ];

        if ($mfa['need']) {
            if (!$mfa['secure_phone']) {
                throw new \RuntimeException('郑州大学统一身份认证未提供可用的短信安全验证方式');
            }

            $challenge = $this->initializeSecurePhone($mfa['state'], $cookieJar);
            $context['attest_server_url'] = $challenge['attest_server_url'];
            $context['gid'] = $challenge['gid'];
            $context['cookies'] = $this->cookieValues($cookieJar);

            throw new MfaRequiredException($context, $challenge['secure_phone']);
        }

        return $this->submitLogin($username, $context, $cookieJar);
    }

    public function sendMfaCode(array $context): array
    {
        $cookieJar = $this->cookieJar($context);
        $result = $this->mfaApiRequest(
            $context,
            '/api/guard/securephone/send',
            ['gid' => $this->contextValue($context, 'gid')],
            $cookieJar
        );

        if ((string) ($result['code'] ?? '') !== '0') {
            if (($result['data']['result'] ?? '') === 'expired') {
                throw new \RuntimeException('郑州大学短信安全验证已过期，请重新登录');
            }

            throw new \RuntimeException('郑州大学短信验证码发送失败');
        }

        $context['cookies'] = $this->cookieValues($cookieJar);

        return $context;
    }

    public function verifyMfaCode(array $context, string $code): ?array
    {
        $cookieJar = $this->cookieJar($context);
        $result = $this->mfaApiRequest(
            $context,
            '/api/guard/securephone/valid',
            [
                'gid' => $this->contextValue($context, 'gid'),
                'code' => $code,
            ],
            $cookieJar
        );

        if ((string) ($result['code'] ?? '') !== '0') {
            if (($result['data']['result'] ?? '') === 'expired') {
                throw new \RuntimeException('郑州大学短信安全验证已过期，请重新登录');
            }

            return null;
        }

        if ((string) ($result['data']['status'] ?? '') !== '2') {
            return null;
        }

        $context['cookies'] = $this->cookieValues($cookieJar);

        return $context;
    }

    public function completeMfaLogin(string $username, array $context): bool
    {
        return $this->submitLogin($username, $context, $this->cookieJar($context));
    }

    private function submitLogin(string $username, array $context, CookieJar $cookieJar): bool
    {
        $response = Http::withHeaders(array_merge($this->headers(), [
            'Origin' => self::BASE_URL,
            'Referer' => self::LOGIN_URL,
        ]))
            ->withOptions(array_merge($this->requestOptions($cookieJar), [
                'allow_redirects' => false,
            ]))
            ->asForm()
            ->post(self::LOGIN_URL, [
                'username' => $username,
                'password' => $this->contextValue($context, 'encrypted_password'),
                'captcha' => '',
                'currentMenu' => '1',
                'failN' => '0',
                'mfaState' => $this->contextValue($context, 'mfa_state'),
                'execution' => $this->contextValue($context, 'execution'),
                '_eventId' => 'submit',
                'geolocation' => '',
                'fpVisitorId' => '',
                'trustAgent' => '',
                'submit1' => 'Login1',
            ]);

        $body = $response->body();
        $errorText = implode("\n", $this->loginErrors($body));
        if ($response->status() === 401
            && preg_match('/账号或密码错误|用户名或密码错误|账号不存在|用户不存在|密码错误/u', $errorText)) {
            return false;
        }

        if ($this->hasTicketGrantingCookie($cookieJar)) {
            return true;
        }

        $location = (string) $response->header('Location');
        if ($response->status() >= 300
            && $response->status() < 400
            && strpos($location, 'ticket=ST-') !== false) {
            return true;
        }

        if ($response->successful()
            && strpos($body, 'id="fm1"') === false
            && strpos($body, '登录成功') !== false) {
            return true;
        }

        if (strpos($errorText, '验证码') !== false) {
            throw new \RuntimeException('郑州大学统一身份认证当前要求验证码，暂时无法自动认证');
        }

        throw new \RuntimeException(
            '郑州大学统一身份认证返回了无法识别的登录结果（状态码 ' . $response->status() . '）'
        );
    }

    private function encryptPassword(string $password, CookieJar $cookieJar): string
    {
        if (!function_exists('openssl_pkey_get_public')
            || !function_exists('openssl_public_encrypt')) {
            throw new \RuntimeException('PHP OpenSSL 扩展不可用，无法认证郑州大学账号');
        }

        $response = Http::withHeaders(array_merge($this->headers(), [
            'Referer' => self::LOGIN_URL,
        ]))
            ->withOptions($this->requestOptions($cookieJar))
            ->get(self::PUBLIC_KEY_URL);

        $publicKey = trim($response->body());
        if (!$response->successful() || $publicKey === '') {
            throw new \RuntimeException('郑州大学统一身份认证未返回密码加密公钥');
        }

        $key = openssl_pkey_get_public($publicKey);
        $encrypted = '';
        if ($key === false
            || !openssl_public_encrypt($password, $encrypted, $key, OPENSSL_PKCS1_PADDING)) {
            throw new \RuntimeException('无法加密郑州大学统一身份认证密码');
        }

        return '__RSA__' . base64_encode($encrypted);
    }

    private function detectMfa(
        string $username,
        string $password,
        CookieJar $cookieJar
    ): array {
        $response = Http::withHeaders(array_merge($this->headers(), [
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Origin' => self::BASE_URL,
            'Referer' => self::LOGIN_URL,
            'X-Requested-With' => 'XMLHttpRequest',
        ]))
            ->withOptions($this->requestOptions($cookieJar))
            ->asForm()
            ->post(self::MFA_DETECT_URL, [
                'username' => $username,
                'password' => $password,
                'fpVisitorId' => '',
            ]);

        $data = $this->jsonData($response, '安全检测');
        $state = (string) ($data['state'] ?? '');
        if ($state === '') {
            throw new \RuntimeException('郑州大学统一身份认证安全检测未返回状态令牌');
        }

        return [
            'state' => $state,
            'need' => ($data['need'] ?? false) === true,
            'secure_phone' => ($data['mfaTypeSecurePhone'] ?? false) === true,
        ];
    }

    private function initializeSecurePhone(string $state, CookieJar $cookieJar): array
    {
        $response = Http::withHeaders(array_merge($this->headers(), [
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Referer' => self::LOGIN_URL,
            'X-Requested-With' => 'XMLHttpRequest',
        ]))
            ->withOptions($this->requestOptions($cookieJar))
            ->get(self::MFA_INIT_URL . '?state=' . rawurlencode($state));

        $data = $this->jsonData($response, '短信安全验证初始化');
        $attestServerUrl = $this->normalizeMfaServerUrl(
            (string) ($data['attestServerUrl'] ?? '')
        );
        $gid = (string) ($data['gid'] ?? '');
        $securePhone = (string) ($data['securePhone'] ?? '');

        if ($attestServerUrl === null) {
            throw new \RuntimeException('郑州大学统一身份认证返回了无效的短信验证服务器地址');
        }
        if ($gid === '') {
            throw new \RuntimeException('郑州大学统一身份认证未返回短信验证挑战编号');
        }
        if ($securePhone === '') {
            throw new \RuntimeException('该郑州大学账号未绑定可用于安全验证的手机');
        }

        return [
            'attest_server_url' => $attestServerUrl,
            'gid' => $gid,
            'secure_phone' => $securePhone,
        ];
    }

    private function mfaApiRequest(
        array $context,
        string $path,
        array $data,
        CookieJar $cookieJar
    ): array {
        $serverUrl = $this->normalizeMfaServerUrl(
            $this->contextValue($context, 'attest_server_url')
        );
        if ($serverUrl === null) {
            throw new \RuntimeException('郑州大学短信安全验证服务器地址无效');
        }

        $response = Http::withHeaders([
            'User-Agent' => $this->headers()['User-Agent'],
            'Accept' => 'application/json, text/plain, */*',
            'Origin' => self::BASE_URL,
            'Referer' => self::LOGIN_URL,
        ])
            ->withOptions($this->requestOptions($cookieJar))
            ->post($serverUrl . $path, $data);

        if (!$response->successful()) {
            throw new \RuntimeException('郑州大学短信安全验证接口暂时不可用');
        }

        $result = json_decode($response->body(), true);
        if (!is_array($result) || !array_key_exists('code', $result)) {
            throw new \RuntimeException('郑州大学短信安全验证返回了无法识别的结果');
        }

        return $result;
    }

    private function jsonData($response, string $label): array
    {
        if (!$response->successful()) {
            throw new \RuntimeException('郑州大学统一身份认证' . $label . '接口暂时不可用');
        }

        $result = json_decode($response->body(), true);
        if (!is_array($result)
            || (string) ($result['code'] ?? '') !== '0'
            || !isset($result['data'])
            || !is_array($result['data'])) {
            throw new \RuntimeException('郑州大学统一身份认证返回了无法识别的' . $label . '结果');
        }

        return $result['data'];
    }

    private function cookieJar(array $context): CookieJar
    {
        $cookies = $context['cookies'] ?? [];
        if (!is_array($cookies)) {
            throw new \RuntimeException('郑州大学统一身份认证会话信息无效');
        }

        return CookieJar::fromArray($cookies, 'cas.s.zzu.edu.cn');
    }

    private function cookieValues(CookieJar $cookieJar): array
    {
        $values = [];
        foreach ($cookieJar->toArray() as $cookie) {
            if (isset($cookie['Name'], $cookie['Value'])) {
                $values[(string) $cookie['Name']] = (string) $cookie['Value'];
            }
        }

        return $values;
    }

    private function contextValue(array $context, string $key): string
    {
        $value = $context[$key] ?? null;
        if (!is_string($value) || $value === '') {
            throw new \RuntimeException('郑州大学统一身份认证挑战信息已失效');
        }

        return $value;
    }

    private function normalizeMfaServerUrl(string $url): ?string
    {
        $url = rtrim($url, '/');
        if ($url === '/attest' || $url === '/mf') {
            $url = self::BASE_URL . $url;
        }

        return in_array($url, self::MFA_SERVER_URLS, true) ? $url : null;
    }

    private function hasTicketGrantingCookie(CookieJar $cookieJar): bool
    {
        return $cookieJar->getCookieByName('TGC') !== null
            || $cookieJar->getCookieByName('CASTGC') !== null;
    }

    private function loginErrors(string $html): array
    {
        if (!preg_match('/\bvar\s+errors\s*=\s*(\[[^;]*\])\s*;/i', $html, $match)) {
            return [];
        }

        $errors = json_decode($match[1], true);
        if (!is_array($errors)) {
            return [];
        }

        return array_map('strval', $errors);
    }

    private function inputValue(string $html, string $name): ?string
    {
        if (!preg_match(
            '/<input\b(?=[^>]*\bname=["\']' . preg_quote($name, '/') . '["\'])[^>]*>/i',
            $html,
            $input
        )) {
            return null;
        }

        if (!preg_match('/\bvalue=["\']([^"\']*)["\']/i', $input[0], $value)) {
            return '';
        }

        return html_entity_decode($value[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    private function requestOptions(CookieJar $cookieJar): array
    {
        return [
            'cookies' => $cookieJar,
            'timeout' => 30,
            'connect_timeout' => 10,
        ];
    }

    private function headers(): array
    {
        return [
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36',
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language' => 'zh-CN,zh;q=0.9,en;q=0.8',
        ];
    }
}
