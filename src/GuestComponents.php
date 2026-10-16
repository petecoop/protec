<?php

declare(strict_types=1);

namespace Petecoop\Protec;

class GuestComponents
{
    public const FILAMENT = [
        \Filament\Auth\Pages\Login::class,
        \Filament\Auth\Pages\Register::class,
        \Filament\Auth\Pages\PasswordReset\RequestPasswordReset::class,
        \Filament\Auth\Pages\PasswordReset\ResetPassword::class,
        \Filament\Livewire\Notifications::class,
    ];
}
