-module(firebase_message).

-export([send/3]).


send(Project, JWT, Message) ->
    Path = <<"https://fcm.googleapis.com/v1/projects/", Project/binary, "/messages:send">>,
    Opts = #{close => true,
             headers => #{<<"Authorization">> => <<"Bearer ", JWT/binary>>,
                          <<"Content-Type">> => <<"application/json">>}},
    case shttpc:post(Path, Message, Opts) of
        #{status := {200, _}, body := Body} ->
            {ok, 200, Body};
        #{status := {Code, _}, body := Body} ->
            logger:warning("INVALID_ARGUMENT: ~p", [Body]),
            {error, Code, Body};
        Unexpected ->
            logger:warning("Unexpected: ~p", [Unexpected]),
            {error, Unexpected}
    end.
