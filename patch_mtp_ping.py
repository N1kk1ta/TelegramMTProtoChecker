from pathlib import Path

p = Path("mtproto_proxy/src/mtp_ping.erl")
s = p.read_text(encoding="utf-8")
old = '''decode_secret(S) ->
    Lc = string:to_lower(S),
    case Lc of
        [$7 | _] -> decode_b64_secret(S);
        _        -> decode_hex_secret(Lc)
    end.
'''
new = '''decode_secret(S) ->
    %% Check canonical hexadecimal forms before the Base64 heuristic.
    %% A valid 32-character normal secret may legitimately start with "7".
    Lc = string:to_lower(S),
    case {length(Lc), is_hex_string(Lc)} of
        {32, true} ->
            {normal, hex_to_bin(Lc), undefined};
        {34, true} ->
            case lists:prefix("dd", Lc) of
                true -> {secure, hex_to_bin(lists:nthtail(2, Lc)), undefined};
                false -> decode_hex_secret(Lc)
            end;
        {N, true} when N > 34 ->
            case lists:prefix("ee", Lc) of
                true ->
                    Rest = lists:nthtail(2, Lc),
                    SecHex = lists:sublist(Rest, 32),
                    DomHex = lists:nthtail(32, Rest),
                    {fake_tls, hex_to_bin(SecHex), nonempty_domain(hex_to_bin(DomHex))};
                false -> decode_hex_secret(Lc)
            end;
        _ ->
            case Lc of
                [$7 | _] -> decode_b64_secret(S);
                _ -> decode_hex_secret(Lc)
            end
    end.

is_hex_string([]) -> true;
is_hex_string([C | Rest]) when (C >= $0 andalso C =< $9) orelse
                               (C >= $a andalso C =< $f) ->
    is_hex_string(Rest);
is_hex_string([_ | _]) -> false.
'''
if old not in s:
    raise SystemExit('Expected decode_secret block not found; mtp_ping source changed.')
s=s.replace(old,new)
p.write_text(s,encoding='utf-8')
print('Patched mtp_ping.erl')
