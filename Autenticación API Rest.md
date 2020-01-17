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
