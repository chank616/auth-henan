<?php

namespace Blessing\HAuth;

use Blessing\HAuth\Schools\NcwuAuth;
use Blessing\HAuth\Schools\ZzuAuth;
use Blessing\HAuth\Utils\SchoolAuth;

class SchoolRegistry
{
    public const SCHOOLS = [
        'ncwu' => [
            'name' => '华北水利水电大学',
            'email' => '@stu.ncwu.edu.cn',
            'auth' => NcwuAuth::class,
        ],
        'zzu' => [
            'name' => '郑州大学',
            'email' => '@stu.zzu.edu.cn',
            'auth' => ZzuAuth::class,
        ],
    ];

    public static function login(string $school, string $username, string $password): bool
    {
        return self::make($school)->login($username, $password);
    }

    public static function make(string $school): SchoolAuth
    {
        $class = self::SCHOOLS[$school]['auth'] ?? null;
        if ($class === null) {
            throw new \InvalidArgumentException("暂不支持该学校：{$school}");
        }

        $auth = new $class();
        if (!$auth instanceof SchoolAuth) {
            throw new \LogicException("学校认证类必须实现 SchoolAuth：{$class}");
        }

        return $auth;
    }

    public static function names(): array
    {
        return array_map(static function (array $school): string {
            return $school['name'];
        }, self::SCHOOLS);
    }

    public static function emailDomain(string $school): string
    {
        if (!isset(self::SCHOOLS[$school])) {
            throw new \InvalidArgumentException("暂不支持该学校：{$school}");
        }

        return self::SCHOOLS[$school]['email'];
    }
}
