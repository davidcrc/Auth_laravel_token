<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class PasswordReset extends Model
{
    // add password resets
    protected $fillable = [
        'email', 'token'
    ];
}
