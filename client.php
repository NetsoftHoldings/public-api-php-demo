<?php
require_once 'vendor/autoload.php';

use Hubstaff\StateManager;
use Hubstaff\TokenManager;
use Hubstaff\APIManager;

$state_manager = new StateManager(__DIR__ . DIRECTORY_SEPARATOR . 'cache');

$token_manager = new TokenManager($state_manager);

$api = new APIManager($token_manager);

var_dump(
    $api->GET('v2/users/me')['user']
);

$api->GET_paged(function($data) {
    var_dump($data['organizations']);
}, 'v2/organizations');

/* example to create a project
$organization_id = '1';

$body = $api->POST('v2/organizations/'.$organization_id. '/projects', [
    'name' => 'API Project',
]);
var_dump($body);

*/
