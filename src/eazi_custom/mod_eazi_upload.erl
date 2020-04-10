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
         authorize/2,
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
cowboy_router_paths(_Base, _Opts) ->
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
    io:fwrite("~nHeaders:~p~n", [cowboy_req:headers(Req)]),
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
    {Data, Req2} = acc_multipart(Req, []),
	
	[{Headers, Body}] = Data,
	
	{_HeaderPart_1, HeaderPart_2 } = cow_multipart:parse_content_disposition(erlang:term_to_binary(Headers)),
	{<<"filename">>, FilenameBin} = lists:keyfind(<<"filename">>, 1, HeaderPart_2),
	FileName = erlang:binary_to_list(FilenameBin),
    <<"/media/", Path/binary>> = cowboy_req:path(Req),
    DirName = filename:dirname(Path),
    Dir = erlang:binary_to_list(<<?DIR_PREFIX/binary, DirName/binary, "/" >>),
    JID = cowboy_req:header(<<"jid">>, Req, undefined),
    ok = filelib:ensure_dir(Dir),

	%% Put the file into the current directory
	FileWriteRes = file:write_file(Dir ++ FileName, Body),
	spawn(fun() -> create_thumbnail(Dir, FileName, JID) end),
	lager:warning("Recived file has been saved ~p", 
							  [[{headers, Headers},
							  {result, FileWriteRes},
							  {fileName, FileName},
							  {path, os:cmd("pwd")}]
							 ]),
	
	%%{Data, Req2},
    Headers1 = #{<<"content-type">> => <<"application/json">>},
    Req3 = cowboy_req:reply(200, Headers1, <<"{}">>, Req2),
    {stop, Req3, State}.

acc_multipart(Req0, Acc) ->
	case cowboy_req:read_part(Req0) of
		{ok, Headers, Req1} ->
			{ok, Body, Req} = stream_body(Req1, <<>>),
			acc_multipart(Req, [{Headers, Body}|Acc]);
		{done, Req} ->
			{lists:reverse(Acc), Req}
	end.

stream_body(Req0, Acc) ->
	case cowboy_req:read_part_body(Req0) of
		{more, Data, Req} ->
			stream_body(Req, << Acc/binary, Data/binary >>);
		{ok, Data, Req} ->
			{ok, << Acc/binary, Data/binary >>, Req}
	end.

-spec create_thumbnail(Dir :: string(), Filename :: string(), _JId :: binary()) ->
    ok | {error, Reason :: term()}.
create_thumbnail(Dir, Filename, _JId) ->
    ThumbNailDir = Dir ++ "thumbnail/",
    Command = case cow_mimetypes:web(list_to_binary(Filename)) of
        {<<"image">>, _, _} ->
            {ok, image_thumbnail(Dir, Filename, ThumbNailDir)};
        {<<"video">>, _, _} ->
            Duration = video_duration(Dir, Filename),
            Sample = Duration div 5,
            {ok, video_thumbnail(Dir, Filename, ThumbNailDir, Sample)};
        Reason ->
            {error, Reason}
        end,
    io:fwrite("Command:~p", [Command]),
    case Command of
        {ok, Cmd} ->
            Result = os:cmd(Cmd),
            io:fwrite("Result:~p", [Result]);
        {error, Reason1} ->
            {error, Reason1}
    end.

image_thumbnail(Dir, File, ThumbNailDir) ->
    ok = filelib:ensure_dir(ThumbNailDir),
    lists:flatten(["convert -resize 200x200 ", Dir, File,
                   " ", ThumbNailDir, File]).

video_thumbnail(Dir, File, ThumbNailDir, Sample) ->
    FilePrefix = filename:rootname(File),
    FilePath = Dir ++ File,
    ok = filelib:ensure_dir(ThumbNailDir),
    lists:flatten(["ffmpeg -i ", FilePath, " -vf fps=1/",
                    integer_to_list(Sample), " ", ThumbNailDir,
                    FilePrefix, "%01d.jpeg"]).

video_duration(Dir, File) ->
    FilePath = Dir ++ File,
    Cmd = "ffmpeg -i " ++ FilePath ++" 2>&1 | grep Duration | awk '{print $2}' | tr -d ,",
    Result = os:cmd(Cmd),
    [H, M, S, _Mi] = [list_to_integer(X) || X <- string:tokens(Result, ":.\n")],
    S + (M*60) + (H*3600).