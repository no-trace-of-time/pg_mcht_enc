%%%-------------------------------------------------------------------
%%% @author simon
%%% @copyright (C) 2017, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 18. 十月 2017 19:14
%%%-------------------------------------------------------------------
-module(pg_mcht_enc_SUITE).
-include_lib("eunit/include/eunit.hrl").
-author("simon").

%% API
-export([]).

setup() ->
  lager:start(),
%%  pg_mcht_enc:start().
  ok = application:start(pg_mcht_enc),
  ok.

my_test_() ->
  {
    setup
    , fun setup/0
    ,
    {
      inorder,
      [
        fun keys_dir_test_1/0
        , fun pg_mcht_enc:sign_verify_test_1/0
        , fun pg_mcht_enc:verify_hex_test_1/0

      ]
    }
  }.


-define(M, pg_mcht_enc).

keys_dir_test_1() ->
  ok.

