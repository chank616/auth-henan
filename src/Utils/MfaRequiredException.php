<?php

namespace Blessing\HAuth\Utils;

class MfaRequiredException extends \RuntimeException
{
    private $context;
    private $destination;

    public function __construct(array $context, string $destination)
    {
        parent::__construct('学校统一身份认证要求额外安全验证');
        $this->context = $context;
        $this->destination = $destination;
    }

    public function context(): array
    {
        return $this->context;
    }

    public function destination(): string
    {
        return $this->destination;
    }
}
