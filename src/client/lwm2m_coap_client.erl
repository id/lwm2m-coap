%
% The contents of this file are subject to the Mozilla Public License
% Version 1.1 (the "License"); you may not use this file except in
% compliance with the License. You may obtain a copy of the License at
% http://www.mozilla.org/MPL/
%
% Copyright (c) 2015 Petr Gotthard <petr.gotthard@centrum.cz>
%

% convenience functions for building CoAP clients
-module(lwm2m_coap_client).

-export([ping/1, request/2, request/3, request/4, ack/2]).
-export([resolve_uri/1, await_response/5]).

-include("coap.hrl").

ping(Uri) ->
    {Scheme, ChId, _Path, _Query} = resolve_uri(Uri),
    channel_apply(Scheme, ChId,
        fun(Channel) ->
            {ok, Ref} = lwm2m_coap_channel:ping(Channel),
            case await_response(Channel, undefined, [], Ref, <<>>) of
                {error, reset} -> ok;
                _Else -> error
            end
        end).

request(Method, Uri) ->
    request(Method, Uri, #coap_content{}, []).

request(Method, Uri, Content) ->
    request(Method, Uri, Content, []).

request(Method, Uri, Content, Options) ->
    {Scheme, ChId, Path, Query} = resolve_uri(Uri),
    channel_apply(Scheme, ChId,
        fun(Channel) ->
            request_block(Channel, Method, [{uri_path, Path}, {uri_query, Query} | Options], Content)
        end).

request_block(Channel, Method, ROpt, Content) ->
    request_block(Channel, Method, ROpt, undefined, Content).

request_block(Channel, Method, ROpt, Block1, Content) ->
    {ok, Ref} = lwm2m_coap_channel:send(Channel,
        lwm2m_coap_message:set_content(Content, Block1,
            lwm2m_coap_message:request(con, Method, <<>>, ROpt))),
    await_response(Channel, Method, ROpt, Ref, Content).


await_response(Channel, Method, ROpt, Ref, Content) ->
    await_response(Channel, Method, ROpt, Ref, Content, <<>>).

await_response(Channel, Method, ROpt, Ref, Content, Fragment) ->
    receive
        {coap_response, _ChId, Channel, Ref, #coap_message{method={ok, continue}, options=Options}} ->
            case proplists:get_value(block1, Options) of
                {Num, true, Size} ->
                    request_block(Channel, Method, ROpt, {Num+1, false, Size}, Content)
            end;
        {coap_response, _ChId, Channel, Ref, Message=#coap_message{method={ok, Code}, options=Options, payload=Data}} ->
            case proplists:get_value(block2, Options) of
                {Num, true, Size} ->
                    % more blocks follow, ask for more
                    % no payload for requests with Block2 with NUM != 0
                    {ok, Ref2} = lwm2m_coap_channel:send(Channel,
                        lwm2m_coap_message:request(con, Method, <<>>, [{block2, {Num+1, false, Size}}|ROpt])),
                    await_response(Channel, Method, ROpt, Ref2, Content, <<Fragment/binary, Data/binary>>);
                _Else ->
                    % not segmented
                    return_response({ok, Code}, Message#coap_message{payload= <<Fragment/binary, Data/binary>>})
            end;
        {coap_response, _ChId, Channel, Ref, Message=#coap_message{method=Code}} ->
            return_response(Code, Message);
        {coap_error, _ChId, Channel, Ref, reset} ->
            {error, reset}
    end.

return_response({ok, Code}, Message) ->
    {ok, Code, lwm2m_coap_message:get_content(Message)};
return_response({error, Code}, #coap_message{payload= <<>>}) ->
    {error, Code};
return_response({error, Code}, Message) ->
    {error, Code, lwm2m_coap_message:get_content(Message)}.

ack(Channel, Message) ->
    lwm2m_coap_channel:send(Channel,
        lwm2m_coap_message:ack(Message)).


resolve_uri(Uri) ->
    {ok, Parsed} = uri_parse(Uri),
    #{scheme := Scheme, host := Host, path := Path, port := PortNo} = Parsed,
    Scheme =/= coap andalso Scheme =/= coaps andalso error({unexpected_scheme, Scheme}), %% assert
    Query = maps:get(query, Parsed, ""),
    {ok, PeerIP} = inet:getaddr(Host, inet),
    {Scheme, {PeerIP, PortNo}, split_path(Path), split_query(Query)}.

split_path([]) -> [];
split_path([$/]) -> [];
split_path([$/ | Path]) -> split_segments(Path, $/, []).

split_query([]) -> [];
split_query([$? | Path]) -> split_segments(Path, $&, []);
split_query(Path) -> split_segments(Path, $&, []).

split_segments(Path, Char, Acc) ->
    case string:rchr(Path, Char) of
        0 ->
            [make_segment(Path) | Acc];
        N when N > 0 ->
            split_segments(string:substr(Path, 1, N-1), Char,
                [make_segment(string:substr(Path, N+1)) | Acc])
    end.

make_segment(Seg) ->
    list_to_binary(uri_decode(Seg)).

channel_apply(coap, ChId, Fun) ->
    {ok, Sock} = lwm2m_coap_udp_socket:start_link(),
    {ok, Channel} = lwm2m_coap_udp_socket:get_channel(Sock, ChId),
    % send and receive
    Res = apply(Fun, [Channel]),
    % terminate the processes
    lwm2m_coap_channel:close(Channel),
    lwm2m_coap_udp_socket:close(Sock),
    Res;

channel_apply(coaps, {Host, Port}, Fun) ->
    {ok, Sock, Channel} = lwm2m_coap_dtls_socket:connect(Host, Port),
    % send and receive
    Res = apply(Fun, [Channel]),
    % terminate the processes
    lwm2m_coap_channel:close(Channel),
    lwm2m_coap_dtls_socket:close(Sock),
    Res.

%% @doc Decode percent-encoded URI.
%% This is copied from http_uri.erl which has been deprecated since OTP-23
%% The recommended replacement uri_string function is not quite equivalent
%% and not backward compatible.
uri_decode(String) when is_list(String) ->
    do_uri_decode(String);
uri_decode(String) when is_binary(String) ->
    do_uri_decode_binary(String).

do_uri_decode([$%,Hex1,Hex2|Rest]) ->
    [hex2dec(Hex1)*16+hex2dec(Hex2)|do_uri_decode(Rest)];
do_uri_decode([First|Rest]) ->
    [First|do_uri_decode(Rest)];
do_uri_decode([]) ->
    [].

do_uri_decode_binary(<<$%, Hex:2/binary, Rest/bits>>) ->
    <<(binary_to_integer(Hex, 16)), (do_uri_decode_binary(Rest))/binary>>;
do_uri_decode_binary(<<First:1/binary, Rest/bits>>) ->
    <<First/binary, (do_uri_decode_binary(Rest))/binary>>;
do_uri_decode_binary(<<>>) ->
    <<>>.

hex2dec(X) when (X>=$0) andalso (X=<$9) -> X-$0;
hex2dec(X) when (X>=$A) andalso (X=<$F) -> X-$A+10;
hex2dec(X) when (X>=$a) andalso (X=<$f) -> X-$a+10.

%% @doc Parse URI into a map as uri_string:uri_map(), but with two fields
%% normalised: (1): port number is never 'undefined', default ports are used
%% if missing. (2): scheme is always atom.
uri_parse(URI) ->
    try
        {ok, do_parse(uri_string:normalize(URI))}
    catch
        throw : Reason ->
            {error, Reason}
    end.

do_parse({error, Reason, Which}) -> throw({Reason, Which});
do_parse(URI) ->
    %% ensure we return string() instead of binary() in uri_map() values.
    Map = uri_string:parse(unicode:characters_to_list(URI)),
    case maps:is_key(scheme, Map) of
        true ->
            normalise_parse_result(Map);
        false ->
            %% missing scheme, add "http://" and try again
            Map2 = uri_string:parse(unicode:characters_to_list(["http://", URI])),
            normalise_parse_result(Map2)
    end.

normalise_parse_result(#{host := Host, scheme := Scheme0} = Map) ->
    {Scheme, DefaultPort} = atom_scheme_and_default_port(Scheme0),
    Port = case maps:get(port, Map, undefined) of
               N when is_number(N) -> N;
               _ -> DefaultPort
           end,
    Map#{ scheme := Scheme
        , host := maybe_parse_ip(Host)
        , port => Port
        }.

maybe_parse_ip(Host) ->
    case inet:parse_address(Host) of
        {ok, Addr} when is_tuple(Addr) -> Addr;
        {error, einval} -> Host
    end.

%% NOTE: so far we only support http/coap schemes.
atom_scheme_and_default_port(Scheme) when is_list(Scheme) ->
    atom_scheme_and_default_port(list_to_binary(Scheme));
atom_scheme_and_default_port(<<"http">> ) -> {http,   80};
atom_scheme_and_default_port(<<"https">>) -> {https, 443};
atom_scheme_and_default_port(<<"coap">> ) -> {coap,  5683};
atom_scheme_and_default_port(<<"coaps">>) -> {coaps, 5684};
atom_scheme_and_default_port(Other) -> throw({unsupported_scheme, Other}).

-include_lib("eunit/include/eunit.hrl").

% note that the options below must be sorted by the option numbers
resolver_test_()-> [
    ?_assertEqual({coap, {{127,0,0,1},?DEFAULT_COAP_PORT},[], []}, resolve_uri("coap://localhost")),
    ?_assertEqual({coap, {{127,0,0,1},1234},[], []}, resolve_uri("coap://localhost:1234")),
    ?_assertEqual({coap, {{127,0,0,1},?DEFAULT_COAP_PORT},[], []}, resolve_uri("coap://localhost/")),
    ?_assertEqual({coap, {{127,0,0,1},1234},[], []}, resolve_uri("coap://localhost:1234/")),
    ?_assertEqual({coaps, {{127,0,0,1},?DEFAULT_COAPS_PORT},[], []}, resolve_uri("coaps://localhost")),
    ?_assertEqual({coaps, {{127,0,0,1},1234},[], []}, resolve_uri("coaps://localhost:1234")),
    ?_assertEqual({coaps, {{127,0,0,1},?DEFAULT_COAPS_PORT},[], []}, resolve_uri("coaps://localhost/")),
    ?_assertEqual({coaps, {{127,0,0,1},1234},[], []}, resolve_uri("coaps://localhost:1234/")),
    ?_assertEqual({coap, {{127,0,0,1},?DEFAULT_COAP_PORT},[<<"/">>], []}, resolve_uri("coap://localhost/%2F")),
    % from RFC 7252, Section 6.3
    % the following three URIs are equivalent
    ?_assertEqual({coap, {{127,0,0,1},5683},[<<"~sensors">>, <<"temp.xml">>], []},
        resolve_uri("coap://localhost:5683/~sensors/temp.xml")),
    ?_assertEqual({coap, {{127,0,0,1},?DEFAULT_COAP_PORT},[<<"~sensors">>, <<"temp.xml">>], []},
        resolve_uri("coap://LOCALHOST/%7Esensors/temp.xml")),
    ?_assertEqual({coap, {{127,0,0,1},?DEFAULT_COAP_PORT},[<<"~sensors">>, <<"temp.xml">>], []},
        resolve_uri("coap://LOCALHOST/%7esensors/temp.xml")),
    % from RFC 7252, Appendix B
    ?_assertEqual({coap, {{127,0,0,1},61616},[<<>>, <<"/">>, <<>>, <<>>], [<<"//">>,<<"?&">>]},
        resolve_uri("coap://localhost:61616//%2F//?%2F%2F&?%26"))
    ].

% end of file
