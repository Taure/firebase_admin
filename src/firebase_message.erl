-module(firebase_message).

-export([send/3]).


send(Project, JWT, Message) ->
    Path = <<"https://fcm.googleapis.com/v1/projects/", Project/binary, "/messages:send">>,
    Opts = #{close => true,
             headers => #{<<"Authorization">> => <<"Bearer ", JWT/binary>>,
                          <<"Content-Type">> => <<"application/json">>}},
    case shttpc:post(Path, Message, Opts) of
        #{status := {200, _}, body := Body} ->
            logger:info("Message sent. Received: ~p", [Body]),
            Body;
        #{status := {400, _}, body := Body} ->
            logger:warning("INVALID_ARGUMENT: ~p", [Body]),
            {error, invalid_argument};
        #{status := {404, _}, body := Body} ->
            logger:warning("UNREGISTERED: ~p", [Body]),
            {error, unregistered};
        #{status := {403, _}, body := Body} ->
            logger:warning("SENDER_ID_MISMATCH: ~p", [Body]),
            {error, sender_id_mismatch};
        #{status := {429, _}, body := Body} ->
            logger:warning("QUOTA_EXCEEDED: ~p", [Body]),
            {error, quota_exceeded};
        #{status := {503, _}, body := Body} ->
            logger:warning("UNAVAILABLE: ~p", [Body]),
            {error, unavailable};
        #{status := {500, _}, body := Body} ->
            logger:warning("INTERNAL: ~p", [Body]),
            {error, internal};
        #{status := {401, _}, body := Body} ->
            logger:warning("THIRD_PARTY_AUTH_ERROR: ~p", [Body]),
            {error, third_party_auth_error};
        Unexpected ->
            logger:warning("Unexpected: ~p", [Unexpected])
    end.
