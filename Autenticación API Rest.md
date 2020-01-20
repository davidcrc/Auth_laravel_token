Autenticacion utilizando Auth de laravel / Passport

# Instalacion y configuración

1.- Crear un nuevo proyecto

    composer create-project --prefer-dist laravel/laravel apiAuth```

2.- Instalar passport

    composer require laravel/passport

3.- Migrar su DB

    php artisan migrate

4.- Generar las llaves de autenticacion(por defecto estaran en storage)

    php artisan passport:install

5.- En App\User, añadir:

    use Laravel\Passport\HasApiTokens;
    use HasApiTokens, Notifiable;

6.- En app/Providers/AuthServiceProvider, añadir:

    use Laravel\Passport\Passport;
    Passport::routes();

7.- En config/auth.php, modificar el driver a:

    'driver' => 'passport',

#  Creación de las rutas de la API

1.- En routes/api.php, añadir , (Comentar la ruta que se encontraba ahí):

    // Estos van para usuario y contraseña
    Route::group(['prefix' => 'auth'], function () {
    Route::post('login', 'AuthController@login');
    Route::post('signup', 'AuthController@signup');
  
    // Estos se utilizan para ingresar con token
    Route::group(['middleware' => 'auth:api'], function() {
        Route::get('logout', 'AuthController@logout');
        Route::get('user', 'AuthController@user');
    });


2.- Crear un controlador (no se si este ya existía)

    php artisan make:controller AuthController

3.- En AuthController.php, añadir:

    Las funciones : signup(), login(), logout(), user()

- Diferentes configuraciones se realizan con postman, utlizando POST y GET, funciona correctamente.

- Link: 
https://medium.com/@cvallejo/sistema-de-autenticaci%C3%B3n-api-rest-con-laravel-5-6-240be1f3fc7d


# Generación de notificaciones y envio de confirmación por email

1.- Añadir tres campos a la columna User : database/migrations/xxxx_create_users_table.php

    $table->boolean('active')->default(false);
    $table->string('activation_token');
    .
    .
    $table->softDeletes();

2.- Añadir o modifcar en App\User:

    use Illuminate\Database\Eloquent\SoftDeletes;
    
    class User .. (){
        use HasApiTokens, Notifiable, SoftDeletes;
        protected $dates = ['deleted_at'];

        protected $fillable = [
        'name', 'email', 'password', 'active', 'activation_token',
        ];
        protected $hidden = [
            'password', 'remember_token', 'activation_token',
        ];
    }

    - Luego realizar un refresh:
        php artisan migrate:refresh

3.- CREAR UNA NOTIFICATIONS: 

    php artisan make:notification SignupActivate

    - Con lo anterior se creó: app/Notifications/SignupActivate.php
    - Modificar al gusto...

    public function via($notifiable)
    {
        return ['mail'];
    }

    public function toMail($notifiable)
    {
        $url = url('/api/auth/signup/activate/'.$notifiable->activation_token);
        return (new MailMessage)
            ->subject('Confirma tu cuenta')
            ->line('Gracias por suscribirte! Antes de continuar, debes configurar tu cuenta.')
            ->action('Confirmar tu cuenta', url($url))
            ->line('Muchas gracias por utilizar nuestra aplicación!');
    }

    - PARA PODER UTILIZAR EL CORREO HAY QUE IMPORTAR:

        php artisan vendor:publish --tag=laravel-mail

4.- Crear y enviar token para confirmar la cuenta: Modificar en app/Http/Controllers/AuthController.php

    - Para el random hay que instalar: 
        composer require laravel/helpers


    <?php
    ...
    use App\Notifications\SignupActivate;
    use Illuminate\Support\Str;
    class AuthController extends Controller
    {
    ...
        public function signup(Request $request)
        {
            $request->validate([
                'name'      => 'required|string',
                'email'     => 'required|string|email|unique:users',
                'password'  => 'required|string|confirmed',
            ]);
            $user = new User([
                'name'              => $request->name,
                'email'             => $request->email,
                'password'          => bcrypt($request->password),
                'activation_token'  => Str::random(60),
            ]);
            $user->save();
            $user->notify(new SignupActivate($user));
            
            return response()->json(['message' => 'Usuario creado existosamente!'], 201);
        }
    }

5.- Agregar la ruta para la activación de la cuenta:

    - Hay que agregar la nueva ruta signup/activate/{token} en el archivo routes/api.php.

    <?php
    Route::group(['prefix' => 'auth'], function () {
        Route::post('login', 'AuthController@login');
        Route::post('signup', 'AuthController@signup');
        Route::get('signup/activate/{token}', 'AuthController@signupActivate');
    
        Route::group(['middleware' => 'auth:api'], function () {
            Route::get('logout', 'AuthController@logout');
            Route::get('user', 'AuthController@user');
        });
    });

6.- Confirmar cuenta a usuarios activos. En app/Http/Controllers/AuthController.php, añadir:

    public function signupActivate($token)
    {
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json(['message' => 'El token de activación es inválido'], 404);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->save();

        // Aqui retornar un success o lo que se desee
        return $user;
    }

7.- Validación de la cuenta. Modificar app/Http/Controllers/AuthController.php:

    public function login(Request $request)
    {
        $request->validate([
            'email'       => 'required|string|email',
            'password'    => 'required|string',
            'remember_me' => 'boolean',
        ]);
        $credentials = request(['email', 'password']);
        
        // Actualizamos el login para verificar que al activar el token,
        // esta cuenta aún exista.
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;
        
        if (!Auth::attempt($credentials)) {
            return response()->json(['message' => 'No Autorizado'], 401);
        }
        $user = $request->user();
        $tokenResult = $user->createToken('Token Acceso Personal');
        $token = $tokenResult->token;
        if ($request->remember_me) {
            $token->expires_at = Carbon::now()->addWeeks(1);
        }
        $token->save();
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type'   => 'Bearer',
            'expires_at'   => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString(),
        ]);
    }

8.- Configuración archivo ".env"

    Crear una cuenta en mailtrap.io y configurar el .env

    - Diferentes configuraciones se realizan con postman, utlizando POST y GET, funciona correctamente.

    - Link: 
    https://medium.com/@cvallejo/sistema-de-autenticaci%C3%B3n-api-rest-con-laravel-5-6-572a16e3929b

# Generar un Avatar

1.- Instalar: 

    composer require laravolt/avatar

    - Opcional: Publicar para ver su configuracion,
    creará un archivo en : config/laravolt/avatar.php
    
    php artisan vendor:publish -provider="Laravolt\Avatar\ServiceProvider"

    - Adicionalmente una opción es registrar el alias en la carpeta config\app.php: (Verificar si ya esta registrado!)

        'Auth'         => Illuminate\Support\Facades\Auth::class,

    - ADEMAS instalar, luego reiniciar el servicio de PHP:
        sudo apt install imagemagick php-imagick
    
    - Esto debería crear un link a la carpeta public
        php artisan storage:link
    
    

2.- Agregar columna a la tabla usuarios. Añadir en database/migrations/xxxx_create_users_table.php:

    public function up()
    {
        ...

        $table->string('avatar')->default('avatar.png');
        
        ...

    }
    - Luego añadir en App\User.php:
        protected $fillable = [
            'name', 'email', 'password', 'active', 'activation_token', 'avatar',
        ];
    - Por ultimo:
        php artisan migrate:refresh


3.- Crear avatar para cada cuenta de usuario. Modificar en app/Http/Controllers/AuthController.php:
    (El avatar será creado en la carpeta storage/avatars )

    namespace App\Http\Controllers;
    use Avatar;             //add avatar
    use Storage;            //add avatar storage
    use App\User;
    use Carbon\Carbon;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Auth;
    use App\Notifications\SignupActivate;
    class AuthController extends Controller
    {
        ...
        public function signup(Request $request)
        {
            $request->validate([
                'name'      => 'required|string',
                'email'     => 'required|string|email|unique:users',
                'password'  => 'required|string|confirmed',
            ]);
            $user = new User([
                'name'              => $request->name,
                'email'             => $request->email,
                'password'          => bcrypt($request->password),
                'activation_token'  => str_random(60),
            ]);
            $user->save();
            // add avatar, estas dos lineas, crean un avatr con el nombre del usuario
            $avatar = Avatar::create($user->name)->getImageObject()->encode('png');
            Storage::put('avatars/'.$user->id.'/avatar.png', (string) $avatar);
            
            $user->notify(new SignupActivate($user));
            return response()->json(['message' => 'Usuario creado existosamente!'], 201);
        }
    ...


4.- Obtener el avatar de un usuario autenticado

    use Storage;
    ...
    protected $appends = ['avatar_url'];
    protected $dates = ...
    ...
    
    public function getAvatarUrlAttribute()
    {
        return Storage::url('avatars/'.$this->id.'/'.$this->avatar);
    }

- Link: 

    https://medium.com/@cvallejo/sistema-de-autenticaci%C3%B3n-api-rest-con-laravel-5-6-parte-3-50dfbc0ffd1a

# Reestablecer contraseña

1.- Actualizar la migración: Se requerirá una actualización de la tabla password_resets , para ello deberemos crear una nueva migración que incorpore los cambios que necesitamos adicionar a dicha tabla.

    php artisan make:migration alter_create_password_resets_table --table=password_resets

    - Luego, modificar:
        public function up()
        {
            Schema::table('password_resets', function (Blueprint $table){
            $table->increments('id')->first();
            $table->timestamp('updated_at')->nullable();
            });
        } 
        public function down()
        {
            Schema::table('password_resets', function (Blueprint $table) {
                $table->dropColumn('id');
                $table->dropColumn('updated_at');
            });
        }

- Finalmente :

        php artisan migrate

2.- Crear el modelo PasswordReset; creará un archivo en app/PasswordReset.php donde debemos incluir:

    php artisan make:model PasswordReset


- Añadir en app/PasswordReset.php:

        protected $fillable = [
            'email', 'token'
        ];

3.- Crear las Notificaciones; Debemos crear dos notificaciones, ‘PaswordResetRequest’ y ‘PasswordResetSuccess’. Para ello hay que escribir en la terminal los siguientes comandos.

    php artisan make:notification PasswordResetRequest
    php artisan make:notification PasswordResetSuccess


- En el archivo PasswordResetRequest.php debemos agregar el siguiente código:

        <?php
        namespace App\Notifications;
        use Illuminate\Bus\Queueable;
        use Illuminate\Notifications\Notification;
        use Illuminate\Contracts\Queue\ShouldQueue;
        use Illuminate\Notifications\Messages\MailMessage;
        class PasswordResetRequest extends Notification implements ShouldQueue
        {
            use Queueable;
            // add  password resets
            protected $token;
            /**
            * Create a new notification instance.
            *
            * @return void
            */
            // add  password resets
            public function __construct($token)
            {
                $this->token = $token;
            }
            /**
            * Get the notification's delivery channels.
            *
            * @param  mixed  $notifiable
            * @return array
            */
            public function via($notifiable)
            {
                return ['mail'];
            }
            /**
            * Get the mail representation of the notification.
            *
            * @param  mixed  $notifiable
            * @return \Illuminate\Notifications\Messages\MailMessage
            */
            public function toMail($notifiable)
            {
                // add  password resets
                $url = url('/api/password/find/'.$this->token);
                return (new MailMessage)
                    ->line('You are receiving this email because we received a password reset request for your account.')
                    ->action('Reset Password', url($url))
                    ->line('If you did not request a password reset, no further action is required.');
            }
            
            /**
            * Get the array representation of the notification.
            *
            * @param  mixed  $notifiable
            * @return array
            */
            public function toArray($notifiable)
            {
                return [
                    //
                ];
            }
        }

-  en el archivo PasswordResetSuccess.php, modificar
    
        public function toMail($notifiable)
        {
            return (new MailMessage)
                ->line('You are changed your password succeful.')
                ->line('If you did change password, no further action is required.')
                ->line('If you did not change password, protect your account.');
        }

4.- Crear las rutas, modificar routes/api.php:

    Route::group([    
        'namespace' => 'Auth',    
        'middleware' => 'api',    
        'prefix' => 'password'
    ], function () {    
        Route::post('create', 'PasswordResetController@create');
        Route::get('find/{token}', 'PasswordResetController@find');
        Route::post('reset', 'PasswordResetController@reset');
    });

5.- Crear el controlador: PasswordResetController

-  Crear controlador en la ruta app/Http/Controllers/Auth/:

        php artisan make:controller Auth\\PasswordResetController

- Añadir este código:

        <?php
        namespace App\Http\Controllers\Auth;
        use App\User;
        use Carbon\Carbon;
        use App\PasswordReset;
        use Illuminate\Http\Request;
        use App\Http\Controllers\Controller;
        use App\Notifications\PasswordResetRequest;
        use App\Notifications\PasswordResetSuccess;
        class PasswordResetController extends Controller
        {
            /**
            * Create token password reset
            *
            * @param  [string] email
            * @return [string] message
            */
            public function create(Request $request)
            {
                $request->validate([
                    'email' => 'required|string|email',
                ]);
                $user = User::where('email', $request->email)->first();
                if (!$user)
                    return response()->json([
                        'message' => 'We can\'t find a user with that e-mail address.'
                    ], 404);
                $passwordReset = PasswordReset::updateOrCreate(
                    ['email' => $user->email],
                    [
                        'email' => $user->email,
                        'token' => str_random(60)
                    ]
                );
                if ($user && $passwordReset)
                    $user->notify(
                        new PasswordResetRequest($passwordReset->token)
                    );
                return response()->json([
                    'message' => 'We have e-mailed your password reset link!'
                ]);
            }
            /**
            * Find token password reset
            *
            * @param  [string] $token
            * @return [string] message
            * @return [json] passwordReset object
            */
            public function find($token)
            {
                $passwordReset = PasswordReset::where('token', $token)
                    ->first();
                if (!$passwordReset)
                    return response()->json([
                        'message' => 'This password reset token is invalid.'
                    ], 404);
                if (Carbon::parse($passwordReset->updated_at)->addMinutes(720)->isPast()) {
                    $passwordReset->delete();
                    return response()->json([
                        'message' => 'This password reset token is invalid.'
                    ], 404);
                }
                return response()->json($passwordReset);
            }
            /**
            * Reset password
            *
            * @param  [string] email
            * @param  [string] password
            * @param  [string] password_confirmation
            * @param  [string] token
            * @return [string] message
            * @return [json] user object
            */
            public function reset(Request $request)
            {
                $request->validate([
                    'email' => 'required|string|email',
                    'password' => 'required|string|confirmed',
                    'token' => 'required|string'
                ]);
                $passwordReset = PasswordReset::where('token', $request->token)->first();
                if (!$passwordReset)
                    return response()->json([
                        'message' => 'This password reset token is invalid.'
                    ], 404);
                $user = User::where('email', $request->email)->first();
                if (!$user)
                    return response()->json([
                        'message' => 'We can\'t find a user with that e-mail address.'
                    ], 404);
                $user->password = bcrypt($request->password);
                $user->save();
                $passwordReset->delete();
                $user->notify(new PasswordResetSuccess($passwordReset));
                return response()->json($user);
            }
        }

- Link: 

    https://medium.com/@cvallejo/sistema-de-autenticaci%C3%B3n-api-rest-con-laravel-5-6-parte-4-7365cc22d78b

-- PRUEBAS: Durante el uso de postman, recibio bien cuando se enviaan los datos por "params" quiza exista algo en las rutas que no me dejan enviar datos por body->raw !!
