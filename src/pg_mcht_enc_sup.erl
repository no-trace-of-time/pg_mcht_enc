%%%-------------------------------------------------------------------
%% @doc pg_mcht_enc top level supervisor.
%% @end
%%%-------------------------------------------------------------------

-module(pg_mcht_enc_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
  supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

%% Child :: {Id,StartFunc,Restart,Shutdown,Type,Modules}
init([]) ->
  RestartStrategy = xfutils:sup_restart_strategy(),
  Enc = xfutils:child_spec(pg_mcht_enc),
  {ok, {RestartStrategy, [Enc]}}.

%%====================================================================
%% Internal functions
%%====================================================================
