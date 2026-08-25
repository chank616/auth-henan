<?php

namespace Blessing\HAuth\Schools;

use Blessing\HAuth\Utils\SchoolAuth;
use Blessing\HAuth\Utils\KingoDes;
use GuzzleHttp\Cookie\CookieJar;
use Illuminate\Support\Facades\Http;

class NcwuAuth implements SchoolAuth
{
    private const BASE_URL = 'https://jwmis.ncwu.edu.cn/hsjw';
    private const LOGIN_URL = self::BASE_URL . '/cas/login.action';
    private const LOGON_URL = self::BASE_URL . '/cas/logon.action';
    private const TEMP_KEY_URL = self::BASE_URL . '/frame/homepage?method=getTempDeskey';
    private const TEMP_TIME_URL = self::BASE_URL . '/frame/homepage?method=getTempNowtime';

    public function login(string $username, string $password): bool
    {
        $cookieJar = new CookieJar();
        $response = Http::withHeaders($this->headers())
            ->withOptions(['cookies' => $cookieJar, 'timeout' => 30, 'connect_timeout' => 10])
            ->get(self::LOGIN_URL);

        if (!$response->successful()) {
            throw new \RuntimeException('无法访问华水教务系统登录页');
        }

        $sessionCookie = $cookieJar->getCookieByName('JSESSIONID');
        if ($sessionCookie === null) {
            throw new \RuntimeException('华水教务系统未返回登录会话');
        }

        $sessionId = $sessionCookie->getValue();
        $html = $response->body();
        $hiddenFlag = $this->inputValue($html, 'hid_flag', '1');
        if ($hiddenFlag !== '1') {
            throw new \RuntimeException('华水教务系统当前要求验证码，暂时无法自动认证');
        }

        $temporaryKey = $this->getSessionValue(self::TEMP_KEY_URL, $cookieJar, '临时加密密钥');
        $timestamp = $this->getSessionValue(self::TEMP_TIME_URL, $cookieJar, '服务器时间');
        $randNumber = '';
        $passwordProfile = $this->passwordProfile($username, $password);
        $encryptedPassword = $this->usesScanQrPassword($html)
            ? md5(md5($password) . md5(strtolower($randNumber)))
            : $password;

        $rawParams = '_u' . $randNumber . '=' . base64_encode($username . ';;' . $sessionId)
            . '&_p' . $randNumber . '=' . $encryptedPassword
            . '&randnumber=' . $randNumber
            . '&isPasswordPolicy=' . $passwordProfile['policy']
            . '&txt_mm_expression=' . $passwordProfile['expression']
            . '&txt_mm_length=' . $passwordProfile['length']
            . '&txt_mm_userzh=' . $passwordProfile['contains_username']
            . '&hid_flag=' . $hiddenFlag
            . '&hidlag=1'
            . '&hid_dxyzm=' . $this->inputValue($html, 'hid_dxyzm', '');

        $encryptedParams = base64_encode(KingoDes::encrypt($rawParams, $temporaryKey));
        $token = md5(md5($rawParams) . md5($timestamp));

        $response = Http::withHeaders(array_merge($this->headers(), [
            'Accept' => 'application/json, text/javascript, */*; q=0.01',
            'Origin' => 'https://jwmis.ncwu.edu.cn',
            'Referer' => self::LOGIN_URL,
            'X-Requested-With' => 'XMLHttpRequest',
        ]))
            ->withOptions([
                'cookies' => $cookieJar,
                'allow_redirects' => false,
                'timeout' => 30,
                'connect_timeout' => 10,
            ])
            ->asForm()
            ->post(self::LOGON_URL, [
                'params' => $encryptedParams,
                'token' => $token,
                'timestamp' => $timestamp,
                'deskey' => '',
                'ssessionid' => $sessionId,
            ]);

        if (!$response->successful()) {
            throw new \RuntimeException('华水教务系统登录接口暂时不可用');
        }

        $result = json_decode($response->body(), true);
        if (!is_array($result) || !isset($result['status'])) {
            throw new \RuntimeException('华水教务系统返回了无法识别的登录结果');
        }

        $status = (string) $result['status'];
        if ($status === '200') {
            return true;
        }
        if (in_array($status, ['401', '402', '403', '404'], true)) {
            return false;
        }
        if (in_array($status, ['405', '406', '407', '505'], true)) {
            throw new \RuntimeException('华水教务系统要求额外验证，暂时无法自动认证');
        }

        throw new \RuntimeException('华水教务系统拒绝了登录请求（状态码 ' . $status . '）');
    }

    private function getSessionValue(string $url, CookieJar $cookieJar, string $label): string
    {
        $response = Http::withHeaders(array_merge($this->headers(), ['Referer' => self::LOGIN_URL]))
            ->withOptions(['cookies' => $cookieJar, 'timeout' => 30, 'connect_timeout' => 10])
            ->get($url);
        $value = trim($response->body());

        if (!$response->successful() || $value === '') {
            throw new \RuntimeException('华水教务系统未返回' . $label);
        }

        return $value;
    }

    private function passwordProfile(string $username, string $password): array
    {
        $expression = 0;
        foreach (unpack('C*', $password) as $character) {
            if ($character >= 48 && $character <= 57) {
                $expression |= 8;
            } elseif ($character >= 97 && $character <= 122) {
                $expression |= 4;
            } elseif ($character >= 65 && $character <= 90) {
                $expression |= 2;
            } else {
                $expression |= 1;
            }
        }

        $length = strlen($password);
        return [
            'expression' => (string) $expression,
            'length' => (string) $length,
            'contains_username' => stripos(trim($password), trim($username)) !== false ? '1' : '0',
            'policy' => $password !== '' && $password !== $username && $length >= 6 ? '1' : '0',
        ];
    }

    private function inputValue(string $html, string $name, string $default): string
    {
        if (preg_match('/<input\b[^>]*\bname=["\']' . preg_quote($name, '/') . '["\'][^>]*>/i', $html, $input)
            && preg_match('/\bvalue=["\']([^"\']*)["\']/i', $input[0], $value)) {
            return html_entity_decode($value[1], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }

        return $default;
    }

    private function usesScanQrPassword(string $html): bool
    {
        return preg_match('/\bisXqeScanQrCode\s*=\s*true\b/i', $html) === 1;
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
