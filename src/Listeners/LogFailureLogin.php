<?php

namespace Yadahan\AuthenticationLog\Listeners;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Auth\Events\Failed;
use Yadahan\AuthenticationLog\AuthenticationLog;
use Yadahan\AuthenticationLog\Notifications\NewDevice;

class LogFailureLogin
{
    /**
     * The request.
     *
     * @var \Illuminate\Http\Request
     */
    public $request;

    /**
     * Create the event listener.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * Handle the event.
     *
     * @param  Login  $event
     * @return void
     */
    public function handle(Failed $event)
    {
        $guardModel = \Auth::guard($event->guard)->getProvider()->getModel();
        $user = is_null($event->user) ? null : $event->user;
        $ip = $this->request->ip();
        $userAgent = $this->request->userAgent();
        $attempt_log = json_encode($event->credentials);
        $known = ($user)
        ? $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->first()
        : false;

        $authenticationLog = new AuthenticationLog([
            'ip_address' => $ip,
            'user_agent' => $userAgent,
            'attempt_log' => $attempt_log,
            'login_at' => Carbon::now(),
        ]);

        if ($user) {
            $user->authentications()->save($authenticationLog);
        } else {
            AuthenticationLog::record(
                $guardModel,
                0,
                $attempt_log,
                $ip,
                $userAgent,
                Carbon::now()
            );
        }

        if (! $known && config('authentication-log.notify')) {
            $user->notify(new NewDevice($authenticationLog));
        }
    }
}
