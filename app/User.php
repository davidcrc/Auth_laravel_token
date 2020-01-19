<?php

namespace App;

use Laravel\Passport\HasApiTokens;      // add passport

use Illuminate\Database\Eloquent\SoftDeletes;   // add softdeletes
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Storage;                                    // add avatar

class User extends Authenticatable
{
    use HasApiTokens, Notifiable, SoftDeletes;      // add hasApi..and SoftDeletes
    protected $appends = ['avatar_url'];            // add avatar
    protected $dates = ['deleted_at'];              // añade esta fecha de eliminacion parece
    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'name', 'email', 'password', 'active', 'activation_token', 'avatar' // añade 2 utios campos; añadido avatar
    ];

    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'password', 'remember_token', 'activation_token',       // añade activation_token
    ];

    public function getAvatarUrlAttribute()
    {
        return Storage::url('avatars/'.$this->id.'/'.$this->avatar);
    }

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];
}
