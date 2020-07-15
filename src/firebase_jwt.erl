-module(firebase_jwt).

-export([validate_id_token/1]).

-include_lib("public_key/include/public_key.hrl").


validate_id_token(IdToken) ->
   	[Header, Claims, Signature] = binary:split(IdToken, <<$.>>, [global]),
	#{<<"kid">> := KeyId} = json:decode(base64_decode(Header), [maps]),
	#{<<"exp">> := ExpiryTime} = DecodedClaims = json:decode(base64_decode(Claims), [maps]),
	DecodedSignature = base64_decode(Signature),
    case ExpiryTime > os:system_time(seconds) of
        true ->
            GoogleAPISecureTokenURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com",
            #{status := {200, _}, body := RespBody} = shttpc:get(GoogleAPISecureTokenURL),
            #{KeyId := Key} = json:decode(RespBody, [maps]),
            [Certificate] = public_key:pem_decode(Key),
            Cert = public_key:pem_entry_decode(Certificate),
            RSAPubKeyDer = Cert#'Certificate'.tbsCertificate#'TBSCertificate'.subjectPublicKeyInfo#'SubjectPublicKeyInfo'.subjectPublicKey,
            RSAPubKey = public_key:der_decode('RSAPublicKey', RSAPubKeyDer),
            Payload = <<Header/binary, ".", Claims/binary>>,
            case public_key:verify(Payload, sha256, DecodedSignature, RSAPubKey) of
                true -> DecodedClaims;
                _ -> invalid
            end;
        false ->
            time_expired
    end.


base64_decode(Data) ->
  Data1 = << << (urldecode_digit(D)) >> || <<D>> <= Data >>,
  Data2 = case byte_size(Data1) rem 4 of
            2 -> <<Data1/binary, "==">>;
            3 -> <<Data1/binary, "=">>;
            _ -> Data1
          end,
  base64:decode(Data2).


urldecode_digit($_) -> $/;
urldecode_digit($-) -> $+;
urldecode_digit(D)  -> D.