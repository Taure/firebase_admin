-module(firebase_oauth2).

-export([service_account_fcm/1,
         service_account/2]).

service_account_fcm(ServiceJson) ->
    auth(ServiceJson, <<"https://www.googleapis.com/auth/firebase.messaging">>).

service_account(ServiceJson, Scope) ->
    #{<<"client_email">> := ISS,
      <<"token_uri">> := AUD,
      <<"private_key">> := PrivKey} = json:decode(ServiceJson, [maps]),
    Time = os:system_time(seconds),
    Exp = Time + (30*60),
    Claims = #{<<"iss">> => ISS,
               <<"scope">> => Scope,
               <<"aud">> => AUD,
               <<"exp">> => Exp,
               <<"iat">> => Time},
    Jwt = jwerl:sign(Claims, rs256, PrivKey),
    Opts = #{close => true,
             headers => #{<<"Content-Type">> => <<"application/x-www-form-urlencoded">>}},
    Path = <<"https://oauth2.googleapis.com/token">>,
    GrantType = uri_string:compose_query([{<<"grant_type">>, <<"urn:ietf:params:oauth:grant-type:jwt-bearer">>}]),
    AuthData = <<GrantType/binary, "&assertion=", Jwt/binary>>,
    shttpc:post(Path, AuthData, Opts).
        
    
