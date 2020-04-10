%%==============================================================================
%% Copyright 2020 Eazi
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%==============================================================================

-module(mod_http_upload_eazi).
-author('konrad.zemek@erlang-solutions.com').
% -behaviour(mod_http_upload).

-include("mod_http_upload.hrl").

-export([create_slot/6]).
-export([validate/2]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec create_slot(UTCDateTime :: calendar:datetime(), Token :: binary(),
                  Filename :: unicode:unicode_binary(), ContentType :: binary(),
                  Size :: pos_integer(), Opts :: proplists:proplist()) ->
                         {PUTURL :: binary(), GETURL :: binary(),
                          Headers :: #{}} | ok.
create_slot(UTCDateTime, Token, Filename, ContentType, Size, Opts) ->
    lager:warning("Getting options:~p", [UTCDateTime, Token, Filename, ContentType, Size, Opts]),
    EaziOpts = gen_mod:get_opt(eazi, Opts),
    UrlPrefix = list_to_binary(gen_mod:get_opt(url_prefix, EaziOpts)),
    lager:warning("mnesia: records:~p", [mnesia:table_info(file_upload, all)]),
    ExpirationTime = gen_mod:get_opt(expiration_time, Opts, 60),
    UUID = list_to_binary(uuid:uuid_to_string(uuid:get_v4())),
    lager:warning("Composing:~p", [{UrlPrefix, UUID, Filename, ExpirationTime}]),
    case compose_url(UrlPrefix, UUID, Filename, integer_to_binary(ExpirationTime)) of
       {ok, {slot_created, PutUrl, GetUrl}} ->
        {PutUrl, GetUrl, #{}};
       _ ->
           ok
     end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------


compose_url(UrlPrefix, UUID, Filename, ExpirationTime) ->
    Token = list_to_binary(uuid:uuid_to_string(uuid:get_v4())),
    Path = <<"/", UUID/binary, "/", Filename/binary>>,
    Url = <<UrlPrefix/binary, Path/binary>>,
    F = fun() ->
        Rec = #file_upload{path = Path, token = Token, expires = ExpirationTime},
        ok = mnesia:write(file_upload, Rec, write),
        {ok, Rec}
    end,
    try
        {ok, Rec1} = mnesia:activity(transaction, F),
        lager:warning("Wrote record:~p", [Rec1]),
        Query = query_string(#{<<"token">> => Token, <<"expires">> => ExpirationTime}),
        {ok, {slot_created, <<Url/binary, Query/binary>>, Url}}
    catch
        Error:Class:Exception ->
            lager:error("Error in creating slots:~p", [{Error, Class, Exception}]),
        {error, unavailable}
    end.

validate(Path, Queries) ->
    case Queries of
        #{<<"token">> := Token, <<"expires">> := Expires} ->
            case mnesia:dirty_read(file_upload, Path) of
                [] ->
                    {error, not_found};
                [#file_upload{token = Token, expires = Expires}] ->
                    {true, Path};
                Else ->
                    lager:warning("Validation failed:~p", [{Else, Path, Queries}]),
                    {error, unauthorized}
            end;
        _ ->
            {error, not_found}
    end.
            

-spec query_string(Queries :: #{binary() => binary()}) -> QueryString :: binary().
query_string(Queries) ->
    query_string(maps:to_list(Queries), []).


-spec query_string(Queries :: [binary()], Acc :: [binary()]) -> binary().
query_string([], Acc) ->
    iolist_to_binary(lists:reverse(Acc));
query_string([Query | Queries], []) ->
    query_string(Queries, [<<"?", (query_encode(Query))/binary>>]);
query_string([Query | Queries], Acc) ->
    query_string(Queries, [<<"&", (query_encode(Query))/binary>> | Acc]).


-spec query_encode({Key :: binary(), Value :: binary()}) -> QueryComponent :: binary().
query_encode({Key, Value}) ->
    <<(aws_signature_v4:uri_encode(Key))/binary, "=",
      (aws_signature_v4:uri_encode(Value))/binary>>.