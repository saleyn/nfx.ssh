-module(echo_server).
-export([run/0, run/1, stop/0]).

run() ->
    spawn(fun() -> init(100) end).

run(BatchSize) when is_integer(BatchSize) ->
    spawn(fun() -> init(BatchSize) end).

stop() ->
    me ! stop.

init(BatchSize) ->
    register(me, self()),
    loop(undefined, 0, [], BatchSize).

loop(From, N, Acc, BatchSize) ->
    receive
        {From, Msg} when BatchSize > 1, N < 100 ->
            % Got message from the same Pid as last one, and batch size is < 100
            loop(From, N+1, [Msg | Acc], BatchSize);   % Accumulate
        {From, Msg} when BatchSize > 1 ->
            % Batch size exceeded 100 -- send the Acc batch back to client:
            flush(From, [Msg|Acc]),
            loop(From, 0, [], BatchSize);
        {Pid, Msg} ->
            % Msg from some other Pid -- flush the batch, and restart batching
            flush(From, Acc),
            loop(Pid, 1, [Msg], BatchSize);
        stop ->
            io:format("Stop requested -- exiting ~p\n", [self()])
    after 5 ->
        flush(From, Acc),
        loop(undefined, 0, [], BatchSize)
    end.

flush(_Pid, []) ->
    ok;
flush(Pid, Acc) ->
    [Pid ! M || M <- lists:reverse(Acc)],
    ok.
