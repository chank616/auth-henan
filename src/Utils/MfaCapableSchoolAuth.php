<?php

namespace Blessing\HAuth\Utils;

interface MfaCapableSchoolAuth extends SchoolAuth
{
    /**
     * 发送安全验证短信，并返回需要继续保存的挑战上下文。
     */
    public function sendMfaCode(array $context): array;

    /**
     * 验证短信码。成功时返回更新后的上下文，验证码错误时返回 null。
     */
    public function verifyMfaCode(array $context, string $code): ?array;

    /**
     * 安全验证通过后，继续完成学校账号登录。
     */
    public function completeMfaLogin(string $username, array $context): bool;
}
