% $Id$

%% @author Mickael Remond <mickael.remond@process-one.net>

%% @doc
%% The module <strong>{@module}</strong> implements a simple XMPP echo client.
%%
%%
%% <p>
%% This is a example use of the exmpp framework.
%% </p>
%%
%% <p>Usage:
%%    {ok, session} = echo_client:start().
%%    echo_client:stop(Session).
%%
%% <p>This code is copyright Process-one (http://www.process-one.net/)</p>
%% 

-module(echo_client).

-include("exmpp.hrl").
-include("exmpp_client.hrl").

-export([start/0, stop/1]).
-export([init/0]).

start() ->
    spawn(?MODULE, init, []).

stop(EchoClientPid) ->
    EchoClientPid ! stop.


init() ->    
    %% Start XMPP session: Needed to start service (Like
    %% exmpp_stringprep):
    MySession = exmpp_session:start(),
    %% Create XMPP ID (Session Key):
    MyJID = exmpp_jid:make_jid("echo", "localhost", random),
    %% Create a new session with basic (digest) authentication:
    exmpp_session:auth_basic_digest(MySession, MyJID, "password"),
    %% Connect in standard TCP:
    _StreamId = exmpp_session:connect_TCP(MySession, "localhost", 5222),
    session(MySession, MyJID).

%% We are connected. We now log in (and tyr registering if authentication fails)
session(MySession, MyJID) ->
    %% Login with defined JID / Authentication:
    try exmpp_session:login(MySession)
    catch
	throw:{auth_error, 'not-authorized'} ->
	    %% Try creating a new user:
	    io:format("Register~n",[]),
	    %% In a real life client, we should trap error case here
	    %% and print the correct message.
	    exmpp_session:register_account(MySession, "password"),
	    %% After registration, retry to login:
	    exmpp_session:login(MySession)
    end,
    %% We explicitely send presence:
    exmpp_session:send_packet(MySession,
			      exmpp_client_presence:presence(?P_AVAILABLE,
							     "Echo Ready")),
    loop(MySession).

%% Process exmpp packet:
loop(MySession) ->
    receive
        stop ->
            exmpp_session:stop(MySession);
        %% If we receive a message, we reply with the same message
        Record = #received_packet{packet_type=message, raw_packet=Packet} ->
            io:format("~p~n", [Record]),
            echo_packet(MySession, Packet),
            loop(MySession);
        Record ->
            io:format("~p~n", [Record]),
            loop(MySession)
    end.
   
%% Send the same packet back for each message received
echo_packet(MySession, Packet) ->
    From = exmpp_xml:get_attribute(Packet, from),
    To = exmpp_xml:get_attribute(Packet, to),
    TmpPacket = exmpp_xml:set_attribute(Packet, from, To),
    TmpPacket2 = exmpp_xml:set_attribute(TmpPacket, to, From),
    NewPacket = exmpp_xml:remove_attribute(TmpPacket2, id),
    exmpp_session:send_packet(MySession, NewPacket).