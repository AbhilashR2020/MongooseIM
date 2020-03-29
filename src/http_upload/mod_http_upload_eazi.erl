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
-behaviour(mod_http_upload).

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
                          Headers :: #{binary() => binary()}}.
create_slot(UTCDateTime, Token, Filename, ContentType, Size, Opts) ->
    lager:warning("Getting options:~p", [UTCDateTime, Token, Filename, ContentType, Size, Opts]),
    EaziOpts = gen_mod:get_opt(eazi, Opts),
    UrlPrefix = list_to_binary(gen_mod:get_opt(url_prefix, EaziOpts)),
    lager:warning("mnesia: records:~p", [mnesia:table_info(file_upload, all)]),
    ExpirationTime = gen_mod:get_opt(expiration_time, Opts, 60),
    AddACL = proplists:get_value(add_acl, EaziOpts, true),
    BucketNode =  proplists:get_value(bucket_node, EaziOpts),
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

-spec create_queries(UTCDateTime :: calendar:datetime(), AccessKeyId :: binary(),
                     Region :: binary(), ExpirationTime :: pos_integer(),
                     ExpectedHeaders :: #{binary() => binary()}, AddACL :: boolean()) ->
                            Queries :: #{binary() => binary()}.
create_queries(UTCDateTime, AccessKeyId, Region, ExpirationTime, ExpectedHeaders, AddACL) ->
    Scope = aws_signature_v4:compose_scope(UTCDateTime, Region, <<"s3">>),
    SignedHeadersSemi = << <<H/binary, ";">> || H <- maps:keys(ExpectedHeaders) >>,
    SignedHeaders = binary_part(SignedHeadersSemi, 0, byte_size(SignedHeadersSemi) - 1),
    WithAcl = maps:from_list([{<<"x-amz-acl">>, <<"public-read">>} || AddACL]),
    WithAcl#{
       <<"X-Amz-Algorithm">> => <<"AWS4-HMAC-SHA256">>,
       <<"X-Amz-Credential">> => <<AccessKeyId/binary, "/", Scope/binary>>,
       <<"X-Amz-Date">> => aws_signature_v4:datetime_iso8601(UTCDateTime),
       <<"X-Amz-Expires">> => integer_to_binary(ExpirationTime),
       <<"X-Amz-SignedHeaders">> => SignedHeaders
     }.


-spec get_expected_headers(Scheme :: http | https | atom(),
                           Host :: unicode:unicode_binary(),
                           Port :: inet:port_number(),
                           Size :: pos_integer(),
                           ContentType :: binary() | undefined) ->
                                  Headers :: #{binary() => binary()}.
get_expected_headers(Scheme, Host, Port, Size, undefined) ->
    #{<<"host">> => with_port_component(Scheme, Host, Port),
      <<"content-length">> => integer_to_binary(Size)};
get_expected_headers(Scheme, Host, Port, Size, ContentType) ->
    maps:put(<<"content-type">>, ContentType,
             get_expected_headers(Scheme, Host, Port, Size, undefined)).


-spec extract_uri_params(BucketURL :: unicode:unicode_binary(), Token :: binary(),
                         Filename :: unicode:unicode_binary()) ->
                                {Scheme :: http | https | atom(), Host :: unicode:unicode_binary(),
                                 Port :: inet:port_number(), Path :: unicode:unicode_binary()}.
extract_uri_params(BucketURL, Token, Filename) ->
    {ok, {Scheme, [], Host, Port, Path0, []}} = http_uri:parse(binary_to_list(BucketURL)),
    KeylessPath = trim_slash(list_to_binary(Path0)),
    EscapedFilename = aws_signature_v4:uri_encode(Filename),
    Path = <<KeylessPath/binary, "/", Token/binary, "/", EscapedFilename/binary>>,
    {Scheme, list_to_binary(Host), Port, Path}.


compose_url(UrlPrefix, UUID, Filename, ExpirationTime) ->
    Token = list_to_binary(uuid:uuid_to_string(uuid:get_v4())),
    Path = <<"/", UUID/binary, "/", Filename/binary>>,
    Url = <<UrlPrefix/binary, Path/binary>>,
    F = fun() ->
        Rec = #file_upload{path = Path, token = Token, expires = ExpirationTime},
        ok = mnesia:write(file_upload, Rec, write),
        {ok, Rec}
    end,
    {ok, Rec1} = mnesia:activity(transaction, F),
    lager:warning("Wrote record:~p", [Rec1]),
    Query = query_string(#{<<"token">> => Token, <<"expires">> => ExpirationTime}),
    {ok, {slot_created, <<Url/binary, Query/binary>>, Url}}.

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


-spec with_port_component(Scheme :: http | https | atom(),
                          Host :: unicode:unicode_binary(),
                          Port :: inet:port_number()) -> binary().
with_port_component(Scheme, Host, Port) ->
    case lists:keyfind(Scheme, 1, http_uri:scheme_defaults()) of
        {Scheme, Port} -> Host;
        _ -> <<Host/binary, ":", (integer_to_binary(Port))/binary>>
    end.


%% Path has always at least one byte ("/")
-spec trim_slash(binary()) -> binary().
trim_slash(Data) ->
    case binary:last(Data) of
        $/ -> erlang:binary_part(Data, 0, byte_size(Data) - 1);
        _ -> Data
    end.
