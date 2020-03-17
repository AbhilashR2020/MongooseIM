%%==============================================================================
%% Copyright 2020 Eazi ai
%%
%% Properity code
%%==============================================================================


-module(mod_eazi_upload).
-author('maru@eazi.ai').
-behaviour(cowboy_rest).

-include_lib("kernel/include/file.hrl").

%% ejabberd_cowboy exports
-export([cowboy_router_paths/2]).

%% cowboy_rest exports
-export([allowed_methods/2,
         content_types_provided/2,
         terminate/3,
         init/2,
         options/2,
         content_types_accepted/2,
         delete_resource/2,
         resource_exists/2,
         is_authorized/2]).
%% local callbacks
-export([download/2, upload/2]).
-export([create_thumbnail/3]).
-include("mongoose_api.hrl").
-include("mongoose.hrl").
-define(DIR_PREFIX, <<"./">>).
-import(mongoose_api_common, [error_response/3,
                              error_response/4,
                              action_to_method/1,
                              method_to_action/1,
                              error_code/1,
                              process_request/4,
                              parse_request_body/1]).

-type credentials() :: {Username :: binary(), Password :: binary()} | any.

%%--------------------------------------------------------------------
%% ejabberd_cowboy callbacks
%%--------------------------------------------------------------------

%% @doc This is implementation of ejabberd_cowboy callback.
%% Returns list of all available http paths.
-spec cowboy_router_paths(ejabberd_cowboy:path(), ejabberd_cowboy:options()) ->
    ejabberd_cowboy:implemented_result().
cowboy_router_paths(Base, Opts) ->
    ejabberd_hooks:add(register_command, global, mongoose_api_common, reload_dispatches, 50),
    ejabberd_hooks:add(unregister_command, global, mongoose_api_common, reload_dispatches, 50),
        try
            [{"/media/[...]", ?MODULE, []}]
        catch
            _:Err:StackTrace ->
                ?ERROR_MSG("Error occured when getting the commands list: ~p~n~p",
                           [Err, StackTrace]),
                []
        end.

%%--------------------------------------------------------------------
%% cowboy_rest callbacks
%%--------------------------------------------------------------------

init(Req, Opts) ->
    lager:info("upload options:~p", [Opts]),
    {cowboy_rest, Req, Opts}.

options(Req, State) ->
    Req1 = set_cors_headers(Req),
    {ok, Req1, State}.

set_cors_headers(Req) ->
    Req1 = cowboy_req:set_resp_header(<<"Access-Control-Allow-Methods">>,
                                      <<"GET, OPTIONS, PUT, DELETE">>, Req),
    Req2 = cowboy_req:set_resp_header(<<"Access-Control-Allow-Origin">>,
                                      <<"*">>, Req1),
    cowboy_req:set_resp_header(<<"Access-Control-Allow-Headers">>,
                               <<"Content-Type">>, Req2).

allowed_methods(Req, State) ->
    {[<<"OPTIONS">>, <<"GET">>, <<"POST">>, <<"DELETE">>], Req, State}.

content_types_provided(Req, State) ->
  Path = cowboy_req:path(Req),
  lager:warning("Path requested:~p Opts~p", [Path, State]),
  {[{cow_mimetypes:web(Path), download}], Req, State}.
    
content_types_accepted(Req, State) ->
    CTA = [{'*', upload}],
    {CTA, Req, State}.

terminate(_Reason, _Req, _State) ->
    ok.

%% @doc Called for a method of type "DELETE"
delete_resource(Req, #http_api_state{command_category = Category,
                                     command_subcategory = SubCategory,
                                     bindings = B} = State) ->
    Arity = length(B),
    Cmds = mongoose_commands:list(admin, Category, method_to_action(<<"DELETE">>), SubCategory),
    [Command] = [C || C <- Cmds, mongoose_commands:arity(C) == Arity],
    process_request(<<"DELETE">>, Command, Req, State).

resource_exists(Req, State) ->
    case cowboy_req:method(Req) of
        <<"GET">> ->
            <<"/media/", Path/binary>> = cowboy_req:path(Req),
            {ok, Cwd} = file:get_cwd(),
            FullPath = filename:join([Cwd, ?DIR_PREFIX, Path]),
            lager:warning("Path:~p", [FullPath]),
            case file:read_file_info(FullPath) of
                {ok, _} -> {true, Req, State};
                _ -> false
            end;
        _ ->
            {true, Req, State}
    end.

%%--------------------------------------------------------------------
%% Authorization
%%--------------------------------------------------------------------

% @doc Cowboy callback
is_authorized(Req, State) ->
    <<"/media", Path/binary>> = cowboy_req:path(Req),
    Query = maps:from_list(cowboy_req:parse_qs(Req)),
    lager:warning("Path:~p", [{Path, Query}]),
    case cowboy_req:method(Req) of
        <<"POST">> ->
            case mod_http_upload_eazi:validate(Path, Query) of
                {true, _Path1} ->
                    lager:warning("Returning true"),
                    {true, Req, State};
                {error, _Reason} ->
                    lager:warning("Returning false"),
                    {{false, <<>>}, Req, State}
            end;
        <<"GET">> ->
            {true, Req, State};
        _ ->
            {{false, <<>>}, Req, State}
    end.
    % ControlCreds = get_control_creds(State),
    % AuthDetails = mongoose_api_common:get_auth_details(Req),
    % case authorize(ControlCreds, AuthDetails) of
    %     true ->
    %       ;
    %     false ->
    %         mongoose_api_common:make_unauthorized_response(Req, State)
    % end.

-spec authorize(credentials(), {AuthMethod :: atom(),
                                Username :: binary(),
                                Password :: binary()}) -> boolean().
authorize(any, _) -> true;
authorize(_, undefined) -> false;
authorize(ControlCreds, {AuthMethod, User, Password}) ->
    compare_creds(ControlCreds, {User, Password}) andalso
        mongoose_api_common:is_known_auth_method(AuthMethod).

% @doc Checks if credentials are the same (if control creds are 'any'
% it is equal to everything).
-spec compare_creds(credentials(), credentials() | undefined) -> boolean().
compare_creds({User, Pass}, {User, Pass}) -> true;
compare_creds(_, _) -> false.

get_control_creds(#http_api_state{auth = Creds}) ->
    Creds.

%%--------------------------------------------------------------------
%% Internal funs
%%--------------------------------------------------------------------

%% @doc Called for a method of type "GET"
download(Req, State) ->
  <<"/media/", Path/binary>> = cowboy_req:path(Req),
  {ok, #file_info{size=Size}} = file:read_file_info(Path),
  {ok, Cwd} = file:get_cwd(),
  FullPath = filename:join([Cwd, ?DIR_PREFIX, Path]),
  lager:warning("Path requested:~p MIME: ~p size:~p", [Path, cow_mimetypes:web(Path), Size]),
  lager:warning("Full Path:~p", [FullPath]),
  Req2 = cowboy_req:reply(200, #{<<"content-type">> => <<"application/octet-stream">>}, {sendfile, 0, Size, FullPath}, Req),
  {stop, Req2, State}.

%% @doc Called for a method of type "POST" and "PUT"
upload(Req, State) ->                      
    {ok, Headers, Req2} = cowboy_req:read_part(Req),
    {ok, Data, Req3} = cowboy_req:read_part_body(Req2),
    {file, FileHead, Filename, ContentType}
      = cow_multipart:form_data(Headers),
    <<"/media/", Path/binary>> = cowboy_req:path(Req),
    DirName = filename:dirname(Path),
    Dir = <<?DIR_PREFIX/binary, DirName/binary, "/" >>,
    JID = cowboy_req:header(<<"jid">>, Req, undefined),
    ok = filelib:ensure_dir(Dir),
    lager:warning("Directory created, JID:~p", [JID]),
    io:format("Received ~p file ~p of content-type ~p ~n~n",
      [FileHead, Path, ContentType]),
    file:write_file(Path, Data),
    spawn(fun() -> create_thumbnail(Dir, Filename, JID) end),
    Req4 = cowboy_req:reply(200, Req3),
    {stop, Req4, State}.

-spec handler_path(ejabberd_cowboy:path(), mongoose_commands:t(), [{atom(), term()}]) ->
    ejabberd_cowboy:route().
handler_path(Base, Command, ExtraOpts) ->
    {[Base, mongoose_api_common:create_admin_url_path(Command)],
        ?MODULE, [{command_category, mongoose_commands:category(Command)},
                  {command_subcategory, mongoose_commands:subcategory(Command)} | ExtraOpts]}.

-spec create_thumbnail(Dir ::binary(), Path :: ejabberd_cowboy:path(), _JId :: binary()) ->
    ok | {error, Reason :: term()}.
create_thumbnail(Dir, Filename, _JId) ->
    ThumbNailDir = <<Dir/binary, "thumbnail/">>,
    ok = filelib:ensure_dir(ThumbNailDir),
    CommandBin = <<"convert -resize 200x200 ", Dir/binary, Filename/binary,
                    " ", ThumbNailDir/binary, Filename/binary>>,
    Command = binary_to_list(CommandBin),
    lager:warning("Executing commmand:~p", [Command]),
    try
        case os:cmd(Command) of
            [] ->
                lager:warning("Created thumbnail");
            Else ->
                lager:warning("Cannot create thumbnail:~p", [Else])
        end
    catch
        Err:Reason ->
            lager:error("Cannot create thumbnail:~p", [{Err, Reason}])
    end,
    ok.
