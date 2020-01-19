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

