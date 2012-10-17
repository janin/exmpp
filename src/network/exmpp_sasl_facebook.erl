%% Copyright ProcessOne 2006-2010. All Rights Reserved.
%%
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.

-module(exmpp_sasl_facebook).

-export([
	 mech_client_new/2,
	 mech_step/2,
   encode_proplist/1,
   encode_proplist/2]).


%% @type mechstate() = {state, Step, Nonce, Cnonce, Username, Password, AuthzId, GetPassword, CheckPassword, AuthModule, Host, Domain}
%%     Step = 1 | 2 | 3 | 4 | 5
%%     Nonce = string()
%%     Cnonce = string()
%%     ApiSecret = string()
%%     ApiKey = string()
%%     AuthzId = string()
%%     GetPassword = function()
%%     AuthModule = atom()

-record(state, {step, nonce, cnonce, apikey, secret, authzid, auth_module, rspauth}).

mech_client_new(ApiKey, Secret) ->
    crypto:start(),
    {ok, #state{step = 2,
                cnonce = hex(integer_to_list(random:uniform(18446744073709551616))),
                apikey = ApiKey,
                secret = Secret,
                authzid = ""
		}}.


%% First response from client


encode_proplist({Key, Value}, "") when is_list(Value)->
  Key ++ "=" ++ Value;

encode_proplist({Key, Value}, "") when is_integer(Value)->
  Key ++ "=" ++ integer_to_list(Value);

encode_proplist({_Key, _Value}=KV, Values) when is_list(Values), length(Values) > 0 ->
  Values ++ "&" ++ encode_proplist(KV, "").

encode_proplist(Values) when is_list(Values) ->
  lists:foldl(fun encode_proplist/2, "", Values).

mech_step(#state{step = 2, apikey = ApiKey, secret = Secret, cnonce = Cnonce} = State, ServerOut) ->
    case parse(ServerOut) of
        bad ->
            {error, 'bad-protocol'};
        KeyVals ->
            Nonce = proplists:get_value("nonce", KeyVals),
            ReplyQuery = encode_proplist([{"method", proplists:get_value("method", KeyVals)}, 
                                          {"api_key", ApiKey}, 
                                          {"access_token", Secret}, 
                                          {"v", "1.0"}, 
                                          {"call_id", 0},
                                          {"cnonce", Cnonce}, 
                                          {"nonce", Nonce}]),
           io:format("~p", [ReplyQuery]),
           {continue, ReplyQuery, State#state{step = 4, nonce=Nonce, rspauth = ""}}
    end;

%% Client authenticates server
mech_step(#state{step = 4, secret = UserName, rspauth = RspAuth}, ServerOut) ->
    case parse(ServerOut) of
	bad ->
	    {error, 'bad-protocol'};
	KeyVals ->
            case proplists:get_value("rspauth", KeyVals) of
                RspAuth ->
                    ok;
                _ ->
                    %% Here actually it is the server who was not authenticated
                    {error, 'not-authorized', UserName}
            end
    end;

mech_step(_A, B) ->
    io:format("~p", [B]),
    {error, 'bad-protocol'}.

%% @spec (S) -> [{Key, Value}] | bad
%%     S = string()
%%     Key = string()
%%     Value = string()



%%% Start key=value pair
parse([$\& | Cs]) ->
  parse2(Cs, "", "", []);

parse(Cs) ->
  parse2(Cs, "", "", []).

%% parsed key add value
parse2([$\= | Cs], Key, Value, KV) ->
  parse3(Cs, Key, Value, KV);

parse2([C | Cs], Key, Value, KV) ->
  parse2(Cs, [C|Key], Value, KV).

%%% End
parse3([$\& | Cs], Key, Value, KV) ->
  Ret = [{lists:reverse(Key), lists:reverse(Value)}|KV],
  parse2(Cs, "", "" , Ret);

parse3([], Key, Value, KV) ->
  [{lists:reverse(Key), lists:reverse(Value)}|KV];

parse3([C | Cs], Key, Value, KV) ->
  parse3(Cs, Key, [C|Value], KV). 


%% @hidden

digit_to_xchar(D) when (D >= 0) and (D < 10) ->
    D + 48;
digit_to_xchar(D) ->
    D + 87.

%% @hidden

hex(S) ->
    hex(S, []).

%% @hidden

hex([], Res) ->
    lists:reverse(Res);
hex([N | Ns], Res) ->
    hex(Ns, [digit_to_xchar(N rem 16),
	     digit_to_xchar(N div 16) | Res]).

