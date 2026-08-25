<?php

declare(strict_types=1);

namespace GuzzleHttp\Cookie {
    final class CookieJar
    {
        private $cookies = [];

        public static function fromArray(array $cookies, string $domain): self
        {
            $jar = new self();
            foreach ($cookies as $name => $value) {
                $jar->cookies[(string) $name] = (string) $value;
            }

            return $jar;
        }

        public function absorbSetCookie(string $header): void
        {
            $pair = trim(explode(';', $header, 2)[0]);
            if ($pair === '' || strpos($pair, '=') === false) {
                return;
            }

            [$name, $value] = explode('=', $pair, 2);
            $name = trim($name);
            if ($name === '') {
                return;
            }

            if ($value === '') {
                unset($this->cookies[$name]);
                return;
            }

            $this->cookies[$name] = $value;
        }

        public function getCookieByName(string $name)
        {
            return array_key_exists($name, $this->cookies) ? $this->cookies[$name] : null;
        }

        public function toRequestHeader(): string
        {
            $pairs = [];
            foreach ($this->cookies as $name => $value) {
                $pairs[] = $name . '=' . $value;
            }

            return implode('; ', $pairs);
        }

        public function toArray(): array
        {
            $cookies = [];
            foreach ($this->cookies as $name => $value) {
                $cookies[] = [
                    'Name' => $name,
                    'Value' => $value,
                ];
            }

            return $cookies;
        }
    }
}

namespace Illuminate\Support\Facades {
    use GuzzleHttp\Cookie\CookieJar;

    final class Http
    {
        public static function withHeaders(array $headers): PendingRequest
        {
            return new PendingRequest($headers);
        }
    }

    final class PendingRequest
    {
        private $headers;
        private $options = [];
        private $asForm = false;

        public function __construct(array $headers)
        {
            $this->headers = $headers;
        }

        public function withOptions(array $options): self
        {
            $this->options = array_merge($this->options, $options);

            return $this;
        }

        public function asForm(): self
        {
            $this->asForm = true;

            return $this;
        }

        public function get(string $url): Response
        {
            return $this->request('GET', $url, []);
        }

        public function post(string $url, array $data): Response
        {
            return $this->request('POST', $url, $data);
        }

        private function request(string $method, string $url, array $data): Response
        {
            $cookieJar = $this->options['cookies'] ?? null;
            if ($cookieJar !== null && !$cookieJar instanceof CookieJar) {
                throw new \RuntimeException('测试适配器收到不支持的 CookieJar');
            }

            $responseHeaders = [];
            $handle = curl_init($url);
            if ($handle === false) {
                throw new \RuntimeException('无法初始化 cURL');
            }

            $headers = $this->headers;
            if ($this->asForm && $method === 'POST') {
                $headers['Content-Type'] = 'application/x-www-form-urlencoded';
            } elseif ($method === 'POST') {
                $headers['Content-Type'] = 'application/json; charset=UTF-8';
            }
            if ($cookieJar !== null && $cookieJar->toRequestHeader() !== '') {
                $headers['Cookie'] = $cookieJar->toRequestHeader();
            }

            $headerLines = [];
            foreach ($headers as $name => $value) {
                $headerLines[] = $name . ': ' . $value;
            }

            $followRedirects = $this->options['allow_redirects'] ?? true;
            curl_setopt_array($handle, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => $followRedirects !== false,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_CONNECTTIMEOUT => (int) ($this->options['connect_timeout'] ?? 10),
                CURLOPT_TIMEOUT => (int) ($this->options['timeout'] ?? 30),
                CURLOPT_HTTPHEADER => $headerLines,
                CURLOPT_ENCODING => '',
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (
                    &$responseHeaders,
                    $cookieJar
                ): int {
                    $length = strlen($line);
                    $trimmed = trim($line);

                    if (stripos($trimmed, 'HTTP/') === 0) {
                        $responseHeaders = [];
                        return $length;
                    }

                    if ($trimmed === '' || strpos($trimmed, ':') === false) {
                        return $length;
                    }

                    [$name, $value] = explode(':', $trimmed, 2);
                    $lowerName = strtolower(trim($name));
                    $value = trim($value);
                    $responseHeaders[$lowerName] = $value;

                    if ($lowerName === 'set-cookie' && $cookieJar !== null) {
                        $cookieJar->absorbSetCookie($value);
                    }

                    return $length;
                },
            ]);

            if ($method === 'POST') {
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt(
                    $handle,
                    CURLOPT_POSTFIELDS,
                    $this->asForm
                        ? http_build_query($data, '', '&', PHP_QUERY_RFC3986)
                        : json_encode($data, JSON_UNESCAPED_UNICODE)
                );
            }

            $body = curl_exec($handle);
            if ($body === false) {
                $message = curl_error($handle);
                curl_close($handle);
                throw new \RuntimeException('cURL 请求失败：' . $message);
            }

            $status = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
            curl_close($handle);

            return new Response($status, $body, $responseHeaders);
        }
    }

    final class Response
    {
        private $status;
        private $body;
        private $headers;

        public function __construct(int $status, string $body, array $headers)
        {
            $this->status = $status;
            $this->body = $body;
            $this->headers = $headers;
        }

        public function successful(): bool
        {
            return $this->status >= 200 && $this->status < 300;
        }

        public function status(): int
        {
            return $this->status;
        }

        public function body(): string
        {
            return $this->body;
        }

        public function header(string $name)
        {
            return $this->headers[strtolower($name)] ?? null;
        }
    }
}

namespace {
    use Blessing\HAuth\Schools\ZzuAuth;
    use Blessing\HAuth\Utils\MfaRequiredException;

    function readLineFromTerminal(string $prompt): string
    {
        fwrite(STDOUT, $prompt);
        $value = fgets(STDIN);
        if ($value === false) {
            throw new RuntimeException('无法读取终端输入');
        }

        return rtrim($value, "\r\n");
    }

    function readHiddenPassword(): string
    {
        $stdinStat = fstat(STDIN);
        $interactive = !is_array($stdinStat)
            || (((int) ($stdinStat['mode'] ?? 0) & 0170000) === 0020000);

        if (!$interactive) {
            return readLineFromTerminal('统一认证密码: ');
        }

        if (PHP_OS_FAMILY === 'Windows' && function_exists('proc_open')) {
            $script = <<<'POWERSHELL'
$secure = Read-Host -Prompt 'Password' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))
    [Console]::Out.Write('__PASSWORD__' + $encoded)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
POWERSHELL;
            $encodedCommand = base64_encode(mb_convert_encoding($script, 'UTF-16LE', 'UTF-8'));
            $process = proc_open(
                'powershell.exe -NoProfile -EncodedCommand ' . $encodedCommand,
                [
                    0 => STDIN,
                    1 => ['pipe', 'w'],
                    2 => STDERR,
                ],
                $pipes,
                null,
                null,
                ['bypass_shell' => true]
            );

            if (is_resource($process)) {
                $output = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
                $exitCode = proc_close($process);

                if ($exitCode === 0
                    && preg_match('/__PASSWORD__([A-Za-z0-9+\/=]*)/', $output, $match)) {
                    $password = base64_decode($match[1], true);
                    if ($password !== false) {
                        return $password;
                    }
                }
            }
        }

        if (PHP_OS_FAMILY !== 'Windows' && function_exists('shell_exec')) {
            fwrite(STDOUT, '统一认证密码（输入时隐藏）: ');
            shell_exec('stty -echo');
            try {
                $password = fgets(STDIN);
            } finally {
                shell_exec('stty echo');
                fwrite(STDOUT, PHP_EOL);
            }

            if ($password !== false) {
                return rtrim($password, "\r\n");
            }
        }

        fwrite(STDERR, "无法隐藏密码输入，本次输入会显示在终端中。\n");

        return readLineFromTerminal('统一认证密码: ');
    }

    if (PHP_SAPI !== 'cli') {
        fwrite(STDERR, "此脚本只能通过 PHP CLI 运行。\n");
        exit(2);
    }

    foreach (['curl', 'mbstring', 'openssl'] as $extension) {
        if (!extension_loaded($extension)) {
            fwrite(STDERR, "缺少 PHP 扩展：{$extension}\n");
            exit(2);
        }
    }

    $projectRoot = dirname(__DIR__);
    require_once $projectRoot . '/src/Utils/SchoolAuth.php';
    require_once $projectRoot . '/src/Utils/MfaCapableSchoolAuth.php';
    require_once $projectRoot . '/src/Utils/MfaRequiredException.php';
    require_once $projectRoot . '/src/Schools/ZzuAuth.php';

    fwrite(STDOUT, "郑州大学 Provider 手动集成测试\n");
    fwrite(STDOUT, "凭据仅通过 HTTPS 发送到 cas.s.zzu.edu.cn，不会写入文件或日志。\n\n");

    try {
        do {
            $username = trim(readLineFromTerminal('学号/工号: '));
        } while ($username === '');

        $password = readHiddenPassword();
        if ($password === '') {
            throw new RuntimeException('密码不能为空');
        }

        fwrite(STDOUT, "\n正在认证……\n");
        $auth = new ZzuAuth();
        try {
            $authenticated = $auth->login($username, $password);
            unset($password);
        } catch (MfaRequiredException $challenge) {
            unset($password);
            fwrite(
                STDOUT,
                "郑州大学要求短信安全验证，安全手机：" . $challenge->destination() . PHP_EOL
            );
            $confirmation = strtolower(trim(readLineFromTerminal('发送短信验证码？[y/N]: ')));
            if (!in_array($confirmation, ['y', 'yes'], true)) {
                fwrite(STDOUT, "已取消短信安全验证。\n");
                exit(2);
            }

            $context = $auth->sendMfaCode($challenge->context());
            fwrite(STDOUT, "短信验证码已发送。\n");
            $code = trim(readLineFromTerminal('短信验证码: '));
            $context = $auth->verifyMfaCode($context, $code);
            unset($code);

            if ($context === null) {
                fwrite(STDERR, "测试失败：短信验证码错误或已失效。\n");
                exit(2);
            }

            $authenticated = $auth->completeMfaLogin($username, $context);
            unset($context);
        }

        if ($authenticated) {
            fwrite(STDOUT, "测试通过：Provider 返回 true，统一认证成功。\n");
            exit(0);
        }

        fwrite(STDERR, "测试完成：Provider 返回 false，账号或密码错误。\n");
        exit(1);
    } catch (Throwable $exception) {
        if (isset($password)) {
            unset($password);
        }

        fwrite(STDERR, '测试失败：' . $exception->getMessage() . PHP_EOL);
        exit(2);
    }
}
