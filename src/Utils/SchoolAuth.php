<?php

namespace Blessing\HAuth\Utils;

interface SchoolAuth
{
    public function login(string $username, string $password): bool;
}
