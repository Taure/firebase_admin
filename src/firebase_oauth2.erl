-module(firebase_oauth2).

-export([jwt_fcm/1,
         jwt/2]).

jwt_fcm(ServiceJson) ->
    jwt(ServiceJson, <<"https://www.googleapis.com/auth/firebase.messaging">>).

jwt(ServiceJson, Scope) ->
    #{<<"client_email">> := ISS,
      <<"token_uri">> := AUD,
      <<"private_key">> := PrivKey} = json:decode(ServiceJson, [maps]),
    Time = os:system_time(seconds),
    Exp = Time + 108000,
    Claims = #{<<"iss">> => ISS,
               <<"scope">> => Scope,
               <<"aud">> => AUD,
               <<"exp">> => Exp,
               <<"iat">> => Time},
    jwerl:sign(Claims, rs256, PrivKey).
    