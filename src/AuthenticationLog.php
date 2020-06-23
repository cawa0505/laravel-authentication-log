<?php

namespace Yadahan\AuthenticationLog;

use Illuminate\Database\Eloquent\Model;

class AuthenticationLog extends Model
{
    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'authentication_log';

    /**
     * Indicates if the model should be timestamped.
     *
     * @var bool
     */
    public $timestamps = false;

    /**
     * The attributes that aren't mass assignable.
     *
     * @var array
     */
    // protected $guarded = ['authenticatable_id', 'authenticatable_type'];

    protected $fillable = [
        'authenticatable_type', 'authenticatable_id', 'ip_address',
        'user_agent', 'attempt_log', 'login_at', 'logout_at',
    ];

    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'login_at' => 'datetime',
        'logout_at' => 'datetime',
    ];

    /**
     * Get the authenticatable entity that the authentication log belongs to.
     */
    public function authenticatable()
    {
        return $this->morphTo();
    }

    public static function record($authenticatable_type, $authenticatable_id, $attempt_log, $ip, $user_agent, $time)
    {
        return static::create([
            'authenticatable_type' => $authenticatable_type,
            'authenticatable_id' => $authenticatable_id,
            'attempt_log' => $attempt_log,
            'ip_address' => $ip,
            'user_agent' => $user_agent,
            'login_at' => $time
        ]);
    }
}
