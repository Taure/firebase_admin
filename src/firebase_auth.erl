-module(firebase_auth).

-export([sign_in_custom_token/3,
         refresh_token/2,
         sign_up_email_password/4,
         sign_in_email_password/4,
         sign_in_anonymously/2,
         sign_in_oauth/5,
         fetch_providers_for_email/3,
         send_password_reset_email/4,
         verify_password_reset_code/2,
         confirm_password_reset/3,
         change_email/5,
         change_password/4,
         update_profile/6,
         get_user_data/2,
         link_email_password/5,
         link_oauth_credential/6,
         unlink_provider/3,
         send_email_verification/4,
         confirm_email_verification/2,
         delete_account/2
         ]).

-define(BASEURL, application:get_env(firebase_auth, base_url, <<"https://identitytoolkit.googleapis.com/v1">>)).
-type response() :: {ok, map()} | {error, map()} | {error, {error ,atom()}}.

-spec sign_in_custom_token(ApiKey :: binary(),
                           CustomToken :: binary(),
                           SecureToken :: boolean()) -> response().
sign_in_custom_token(ApiKey, CustomToken, SecureToken) ->
    Body = #{<<"token">> => CustomToken,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:signInWithCustomToken?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec refresh_token(ApiKey :: binary(),
                    RefreshToken :: binary()) ->
                    response().
refresh_token(ApiKey, RefreshToken) ->
    Body = #{<<"grant_type">> => <<"refresh_token">>,
             <<"refresh_token">> => RefreshToken},
    Path = [?BASEURL, <<"/token?key=">>, ApiKey],
    post(Path, content_type(x_www_form), Body).

-spec sign_up_email_password(ApiKey :: binary(),
                             Email :: binary(),
                             Password :: binary(),
                             SecureToken :: boolean()) -> 
                             response().
sign_up_email_password(ApiKey, Email, Password, SecureToken) ->
    Body = #{<<"email">> => Email,
             <<"password">> => Password,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:signUp?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec sign_in_email_password(ApiKey :: binary(), 
                             Email :: binary(), 
                             Password :: binary(), 
                             SecureToken :: boolean()) -> 
                             response().
sign_in_email_password(ApiKey, Email, Password, SecureToken) ->
    Body = #{<<"email">> => Email,
             <<"password">> => Password,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:signInWithPassword?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec sign_in_anonymously(ApiKey :: binary(), 
                          SecureToken :: binary()) -> 
                          response().
sign_in_anonymously(ApiKey, SecureToken) ->
    Body = #{<<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:signUp?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec sign_in_oauth(ApiKey :: binary(),
                    RequestUri :: binary(),
                    PostBody :: map(),
                    SecureToken :: boolean(),
                    ReturnIdpCredential :: boolean()) ->
                    response().
sign_in_oauth(ApiKey, RequestUri, PostBody, SecureToken, ReturnIdpCredential) ->
    Body = #{<<"requestUri">> => RequestUri,
             <<"postBody">> => PostBody,
             <<"returnSecureToken">> => SecureToken,
             <<"returnIdpCredential">> => ReturnIdpCredential},
    Path = [?BASEURL, <<"/accounts:signInWithIdp?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec fetch_providers_for_email(ApiKey :: binary(),
                                Identifier :: binary(),
                                ContinueUri :: binary()) ->
                                response().
fetch_providers_for_email(ApiKey, Identifier, ContinueUri) ->
    Body = #{<<"identifier">> => Identifier,
             <<"continueUri">> => ContinueUri},
    Path = [?BASEURL, <<"/accounts:createAuthUri?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec send_password_reset_email(ApiKey :: binary(),
                                RequestType :: binary(),
                                Email :: binary(),
                                FirebaseLocale :: undefined | binary()) ->
                                response().
send_password_reset_email(ApiKey, RequestType, Email, FirebaseLocale) ->
    Headers = case FirebaseLocale of
                  undefined ->
                        content_type(json);
                  FirebaseLocale ->
                        maps:merge(content_type(json), #{<<"X-Firebase-Locale">> => FirebaseLocale})
              end,
    Body = #{<<"requestType">> => RequestType,
             <<"email">> => Email},
    Path = [?BASEURL, <<"/accounts:sendOobCode?key=">>, ApiKey],
    post(Path, Headers, Body).

-spec verify_password_reset_code(ApiKey :: binary(),
                                 OobCode :: binary()) ->
                                 response().
verify_password_reset_code(ApiKey, OobCode) ->
    Body = #{<<"oobCode">> => OobCode},
    Path = [?BASEURL, <<"/accounts:resetPassword?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec confirm_password_reset(ApiKey :: binary(),
                             OobCode :: binary(),
                             NewPassword :: binary()) ->
                             response().
confirm_password_reset(ApiKey, OobCode, NewPassword) ->
    Body = #{<<"oobCode">> => OobCode,
             <<"newPassword">> => NewPassword},
    Path = [?BASEURL, <<"/accounts:resetPassword?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec change_email(ApiKey :: binary(), 
                   IdToken :: binary(), 
                   Email :: binary(), 
                   SecureToken :: boolean(),
                   FirebaseLocale :: undefined | binary()) ->
                   response().
change_email(ApiKey, IdToken, Email, SecureToken, FirebaseLocale) ->
    Headers = case FirebaseLocale of
                  undefined ->
                        content_type(json);
                  FirebaseLocale ->
                        maps:merge(content_type(json), #{<<"X-Firebase-Locale">> => FirebaseLocale})
              end,
    Body = #{<<"idToken">> => IdToken,
             <<"email">> => Email,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, Headers, Body).

-spec change_password(ApiKey :: binary(), 
                      IdToken :: binary(), 
                      Password :: binary(), 
                      SecureToken :: boolean()) ->
                      response().
change_password(ApiKey, IdToken, Password, SecureToken) ->
    Body = #{<<"idToken">> => IdToken,
             <<"password">> => Password,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec update_profile(ApiKey :: binary(), 
                     IdToken :: binary(), 
                     DisplayName :: binary(),
                     PhotoUrl :: binary(),
                     DeleteAttribute :: binary(),
                     SecureToken :: boolean()) ->
                     response().
update_profile(ApiKey, IdToken, DisplayName, PhotoUrl, DeleteAttribute, SecureToken) ->
    Body = #{<<"idToken">> => IdToken,
             <<"displayName">> => DisplayName,
             <<"photoUrl">> => PhotoUrl,
             <<"deleteAttribute">> => DeleteAttribute,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec get_user_data(ApiKey :: binary(), IdToken :: binary()) -> response().                    
get_user_data(ApiKey, IdToken) ->
    Body = #{<<"idToken">> => IdToken},
    Path = [?BASEURL, <<"/accounts:lookup?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec link_email_password(ApiKey :: binary(),
                          IdToken :: binary(),
                          Email :: binary(),
                          Password :: binary(),
                          SecureToken :: boolean()) ->
                          response().
link_email_password(ApiKey, IdToken, Email, Password, SecureToken) ->
    Body = #{<<"idToken">> => IdToken,
             <<"email">> => Email,
             <<"password">> => Password,
             <<"returnSecureToken">> => SecureToken},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec link_oauth_credential(ApiKey :: binary(),
                            IdToken :: binary(),
                            RequestUri :: binary(),
                            PostBody :: map(),
                            SecureToken :: boolean(),
                            ReturnIdpCredential :: boolean()) ->
                            response().
link_oauth_credential(ApiKey, IdToken, RequestUri, PostBody, SecureToken, ReturnIdpCredential) ->
    Body = #{<<"idToken">> => IdToken,
             <<"requestUri">> => RequestUri,
             <<"postBody">> => PostBody,
             <<"returnSecureToken">> => SecureToken,
             <<"returnIdpCredential">> => ReturnIdpCredential},
    Path = [?BASEURL, <<"/accounts:signInWithIdp?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec unlink_provider(ApiKey :: binary(),
                      IdToken :: binary(),
                      DeleteAttribute :: binary()) ->
                      response().
unlink_provider(ApiKey, IdToken, DeleteAttribute) ->
    Body = #{<<"idToken">> => IdToken,
             <<"deleteAttribute">> => DeleteAttribute},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec send_email_verification(ApiKey :: binary(),
                              IdToken :: binary(),
                              RequestType :: binary(),
                              FirebaseLocale :: undefined | binary()) ->
                              response().
send_email_verification(ApiKey, IdToken, RequestType, FirebaseLocale) ->
    Headers = case FirebaseLocale of
                  undefined ->
                        content_type(json);
                  FirebaseLocale ->
                        maps:merge(content_type(json), #{<<"X-Firebase-Locale">> => FirebaseLocale})
              end,
    Body = #{<<"idToken">> => IdToken,
             <<"requestType">> => RequestType},
    Path = [?BASEURL, <<"/accounts:sendOobCode?key=">>, ApiKey],
    post(Path, Headers, Body).

-spec confirm_email_verification(ApiKey :: binary(),
                                 OobCode :: binary()) ->
                                 response().
confirm_email_verification(ApiKey, OobCode) ->
    Body = #{<<"oobCode">> => OobCode},
    Path = [?BASEURL, <<"/accounts:update?key=">>, ApiKey],
    post(Path, content_type(json), Body).

-spec delete_account(ApiKey :: binary(),
                     IdToken :: binary()) ->
                     response().
delete_account(ApiKey, IdToken) ->
    Body = #{<<"idToken">> => IdToken},
    Path = [?BASEURL, <<"/accounts:delete?key=">>, ApiKey],
    post(Path, content_type(json), Body).



post(Url, Headers, Body) ->
    OPTS = #{close => true,
             headers => Headers},
    case shttpc:post(Url, json:encode(Body, [maps, binary]), OPTS) of
        #{status := {200, _}, body := RespBody} ->
            {ok, json:decode(RespBody, [maps])};
        Error ->
            logger:debug(Error),
            {error, Error}
    end.



content_type(json) ->
    #{<<"Content-Type">> => <<"application/json">>};
content_type(x_www_form) ->
    #{<<"Content-Type">> => <<"x-www-form-urlencoded">>}.
